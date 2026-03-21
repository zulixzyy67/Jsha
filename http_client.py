"""
arch/http_client.py  —  100% Native Async HTTP
================================================
Replaces every `requests.get/post` wrapped in `asyncio.to_thread` /
`ThreadPoolExecutor` with a single shared `aiohttp.ClientSession` that
lives for the lifetime of the bot process.

Key design decisions:
  ① ONE session shared across all concurrent scans — avoids the 65k
     ephemeral-port exhaustion seen when every handler opens its own session.
  ② Connection pool per host (limit=20 total, 10/host) — still allows
     heavy parallel probing without hammering one target.
  ③ Exponential-backoff retry via a thin async decorator — mirrors the
     urllib3.Retry logic from the old requests.Session setup.
  ④ SSL verification is off-by-default (pentest tool) with a clear opt-in.
  ⑤ The `_get_headers()` helper is preserved so callers need no changes.
  ⑥ A context-manager-friendly `ManagedSession` makes unit-testing easy.

Usage:
    from arch.http_client import get, post, session_get, AsyncHTTPClient

    # High-level one-shot helpers (auto-retry, header injection):
    text, status = await get("https://example.com/robots.txt")
    data, status = await post("https://api.example.com/graphql", json={"query": "{__typename}"})

    # Low-level access to the shared session (for streaming, chunked, etc.):
    async with session_get("https://example.com") as resp:
        async for chunk in resp.content.iter_chunked(8192):
            process(chunk)
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional, Tuple

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

logger = logging.getLogger(__name__)

# ── User-agent pool (mirrors _UA_LIST in original) ────────────────────────────
_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]

# ── Default timeouts ──────────────────────────────────────────────────────────
DEFAULT_TIMEOUT = ClientTimeout(
    total=60,
    connect=10,
    sock_connect=10,
    sock_read=30,
)
FAST_TIMEOUT = ClientTimeout(total=10, connect=5)
HEAVY_TIMEOUT = ClientTimeout(total=120, connect=15)


def _make_headers(
    referer: Optional[str] = None,
    bypass_403: bool = False,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """
    Drop-in async replacement for the original _get_headers().
    Generates rotating User-Agent + optional 403-bypass headers.
    """
    ua = random.choice(_UA_LIST)
    headers: Dict[str, str] = {
        "User-Agent":      ua,
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection":      "keep-alive",
        "Cache-Control":   "no-cache",
        "Pragma":          "no-cache",
    }
    if referer:
        headers["Referer"] = referer
    if bypass_403:
        headers.update({
            "X-Forwarded-For":  f"127.0.{random.randint(0,255)}.{random.randint(1,254)}",
            "X-Real-IP":        f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP":      "127.0.0.1",
            "X-Remote-Addr":    "127.0.0.1",
        })
    if extra:
        headers.update(extra)
    return headers


# ═══════════════════════════════════════════════════════════════════════════════
# Shared session singleton
# ═══════════════════════════════════════════════════════════════════════════════

class AsyncHTTPClient:
    """
    Lifecycle-aware aiohttp session singleton.

    Call `await client.start()` once in main(), and `await client.close()`
    in the shutdown hook.  All scan functions call the module-level helpers
    `get()`, `post()`, `head()` which delegate here.
    """

    _instance: Optional["AsyncHTTPClient"] = None

    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None
        self._lock    = asyncio.Lock()

    @classmethod
    def get_instance(cls) -> "AsyncHTTPClient":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def start(self):
        """Create the shared session.  Idempotent."""
        async with self._lock:
            if self._session is None or self._session.closed:
                connector = TCPConnector(
                    limit=100,            # total concurrent connections
                    limit_per_host=20,    # per-host (prevents hammering one target)
                    ttl_dns_cache=300,    # cache DNS for 5 min
                    use_dns_cache=True,
                    ssl=False,            # pentest tool — caller opts in to verify
                    enable_cleanup_closed=True,
                )
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=DEFAULT_TIMEOUT,
                    headers=_make_headers(),
                    trust_env=True,       # respect http_proxy env vars
                )
                logger.info("✅ aiohttp session started (pool limit=%d/host=20)", 100)

    async def close(self):
        async with self._lock:
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None
                logger.info("aiohttp session closed")

    async def _ensure(self):
        if self._session is None or self._session.closed:
            await self.start()
        return self._session

    # ─── Core request method with retry ──────────────────────────────────────

    async def request(
        self,
        method:      str,
        url:         str,
        *,
        retries:     int = 3,
        base_delay:  float = 1.0,
        timeout:     Optional[ClientTimeout] = None,
        headers:     Optional[Dict[str, str]] = None,
        ssl:         bool = False,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        """
        Execute an HTTP request with exponential backoff retry.
        Returns the raw ClientResponse — callers must consume it before
        the connection is returned to the pool (use as async context manager
        or call .read() / .text() / .json() immediately).

        Retries on: 429, 500, 502, 503, 504, connection errors, timeouts.
        Does NOT retry on: 4xx client errors (except 429).
        """
        sess = await self._ensure()
        merged_headers = _make_headers()
        if headers:
            merged_headers.update(headers)

        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                resp = await sess.request(
                    method,
                    url,
                    headers=merged_headers,
                    timeout=timeout or DEFAULT_TIMEOUT,
                    ssl=ssl,
                    allow_redirects=True,
                    **kwargs,
                )
                if resp.status in (429, 500, 502, 503, 504) and attempt < retries:
                    delay = base_delay * (2 ** attempt) + random.uniform(0, 0.3)
                    logger.debug("Retry %d/%d for %s (status=%d) in %.1fs",
                                 attempt + 1, retries, url, resp.status, delay)
                    await resp.release()
                    await asyncio.sleep(delay)
                    continue
                return resp
            except (aiohttp.ClientConnectorError,
                    aiohttp.ServerDisconnectedError,
                    asyncio.TimeoutError) as exc:
                last_exc = exc
                if attempt < retries:
                    delay = base_delay * (2 ** attempt) + random.uniform(0, 0.3)
                    logger.debug("Retry %d/%d for %s (%s) in %.1fs",
                                 attempt + 1, retries, url, type(exc).__name__, delay)
                    await asyncio.sleep(delay)
                else:
                    raise
        raise last_exc  # type: ignore[misc]

    # ─── Convenience helpers (text) ───────────────────────────────────────────

    async def fetch_text(
        self, url: str, *, method: str = "GET",
        timeout: Optional[ClientTimeout] = None, **kwargs
    ) -> Tuple[str, int]:
        """Returns (body_text, status_code)."""
        async with await self.request(method, url, timeout=timeout, **kwargs) as resp:
            text = await resp.text(errors="replace")
            return text, resp.status

    async def fetch_json(
        self, url: str, *, method: str = "GET",
        timeout: Optional[ClientTimeout] = None, **kwargs
    ) -> Tuple[Any, int]:
        """Returns (parsed_json_or_None, status_code)."""
        async with await self.request(method, url, timeout=timeout, **kwargs) as resp:
            try:
                data = await resp.json(content_type=None)
            except Exception:
                data = None
            return data, resp.status

    async def fetch_headers(
        self, url: str, timeout: Optional[ClientTimeout] = None, **kwargs
    ) -> Tuple[Dict[str, str], int]:
        """HEAD request — returns (headers_dict, status)."""
        async with await self.request("HEAD", url, timeout=timeout or FAST_TIMEOUT, **kwargs) as resp:
            return dict(resp.headers), resp.status


# ── Module-level singleton helpers ────────────────────────────────────────────

_client = AsyncHTTPClient.get_instance()


async def get(
    url: str,
    *,
    timeout: Optional[ClientTimeout] = None,
    headers: Optional[Dict[str, str]] = None,
    bypass_403: bool = False,
    **kwargs,
) -> Tuple[str, int]:
    """
    Convenience wrapper: async GET → (text, status_code).
    Drop-in for: `r = requests.get(url, ...); return r.text, r.status_code`
    """
    extra_headers = _make_headers(bypass_403=bypass_403)
    if headers:
        extra_headers.update(headers)
    return await _client.fetch_text(url, timeout=timeout, headers=extra_headers, **kwargs)


async def post(
    url: str,
    *,
    timeout: Optional[ClientTimeout] = None,
    headers: Optional[Dict[str, str]] = None,
    **kwargs,
) -> Tuple[str, int]:
    """
    Convenience wrapper: async POST → (text, status_code).
    """
    return await _client.fetch_text(
        url, method="POST", timeout=timeout, headers=headers, **kwargs
    )


async def get_json(
    url: str,
    *,
    timeout: Optional[ClientTimeout] = None,
    headers: Optional[Dict[str, str]] = None,
    **kwargs,
) -> Tuple[Any, int]:
    """async GET → (json, status_code)."""
    return await _client.fetch_json(url, timeout=timeout, headers=headers, **kwargs)


async def post_json(
    url: str,
    *,
    timeout: Optional[ClientTimeout] = None,
    headers: Optional[Dict[str, str]] = None,
    json_body: Any = None,
    **kwargs,
) -> Tuple[Any, int]:
    """async POST with JSON body → (json, status_code)."""
    return await _client.fetch_json(
        url, method="POST", timeout=timeout, headers=headers,
        json=json_body, **kwargs
    )


async def head(
    url: str,
    *,
    timeout: Optional[ClientTimeout] = None,
    **kwargs,
) -> Tuple[Dict[str, str], int]:
    """async HEAD → (headers, status_code)."""
    return await _client.fetch_headers(url, timeout=timeout or FAST_TIMEOUT, **kwargs)


@asynccontextmanager
async def session_get(url: str, **kwargs):
    """
    Stream-friendly context manager for chunked/large downloads.
    Usage:
        async with session_get(url) as resp:
            data = await resp.read()
    """
    async with await _client.request("GET", url, **kwargs) as resp:
        yield resp


async def probe_many(
    urls: list,
    *,
    method: str = "GET",
    concurrency: int = 20,
    delay: float = 0.1,
    timeout: Optional[ClientTimeout] = None,
    headers: Optional[Dict[str, str]] = None,
) -> list:
    """
    Probe a list of URLs with bounded concurrency.
    Returns list of (url, status_code, body_text | None) tuples.

    Replaces the ThreadPoolExecutor(max_workers=24) patterns used for
    path brute-forcing in discover_api_endpoints and _vuln_scan_sync.
    """
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def _probe(url: str):
        async with sem:
            if delay > 0:
                await asyncio.sleep(delay)
            try:
                text, status = await _client.fetch_text(
                    url, method=method, timeout=timeout or FAST_TIMEOUT,
                    headers=headers
                )
                return url, status, text
            except Exception as exc:
                return url, 0, str(exc)

    tasks = [asyncio.create_task(_probe(u)) for u in urls]
    for coro in asyncio.as_completed(tasks):
        results.append(await coro)
    return results


async def start_client():
    """Call once in main() after the event loop starts."""
    await _client.start()


async def close_client():
    """Call once in shutdown hook."""
    await _client.close()

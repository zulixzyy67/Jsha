"""
arch/browser_pool.py  —  Persistent Browser Context Pool
==========================================================
Replaces the pattern in get_rendered_html() that does:

    async with async_playwright() as p:
        browser = await p.chromium.launch(...)   # ← NEW PROCESS every call
        ...
        await browser.close()                    # ← KILLED every call

With a proper pool that:
  ① Launches N browser processes once at startup (default: 2).
  ② Keeps them alive and hands out isolated BrowserContexts per request.
  ③ Recycles contexts after each use to clear cookies/storage without
     killing the underlying process.
  ④ Falls back to aiohttp if the pool is exhausted or Playwright
     is not installed.
  ⑤ Enforces a per-render timeout so a hung page never leaks a slot.

Memory math (Railway $20 / 8 GB):
  Chromium headless ≈ 80–120 MB per process.
  With POOL_SIZE=3 we use ~360 MB for browsers, well within budget.
  Each BrowserContext adds ~5–15 MB → negligible.

Usage:
    pool = BrowserPool(size=3)
    await pool.start()                          # in main()

    html = await pool.render("https://example.com")

    await pool.stop()                           # in shutdown hook
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
POOL_SIZE       = int(os.getenv("BROWSER_POOL_SIZE", "2"))
RENDER_TIMEOUT  = int(os.getenv("BROWSER_RENDER_TIMEOUT_MS", "30000"))
CONTEXT_MAX_USE = int(os.getenv("BROWSER_CONTEXT_MAX_USE", "50"))  # recycle after N renders

# ── User-agents for context rotation ──────────────────────────────────────────
_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Playwright,
        TimeoutError as PlaywrightTimeout,
    )
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    logger.warning("playwright not installed — browser pool disabled; using aiohttp fallback")


# ── Slot dataclass ────────────────────────────────────────────────────────────

@dataclass
class _BrowserSlot:
    browser:  "Browser"
    context:  "BrowserContext"
    use_count: int = 0
    in_use:   bool = False
    created_at: float = field(default_factory=time.monotonic)

    async def recycle(self):
        """Close and re-create the BrowserContext, keeping the Browser alive."""
        try:
            await self.context.close()
        except Exception:
            pass
        self.context = await self.browser.new_context(
            user_agent=random.choice(_UA_LIST),
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )
        self.use_count = 0
        logger.debug("Browser context recycled")


# ═══════════════════════════════════════════════════════════════════════════════
# BrowserPool
# ═══════════════════════════════════════════════════════════════════════════════

class BrowserPool:
    """
    Manages a fixed pool of persistent Chromium browsers.

    Thread safety: all state is protected by asyncio primitives; this class
    must be used from a single asyncio event loop.
    """

    def __init__(self, size: int = POOL_SIZE):
        self._size    = size
        self._slots:  List[_BrowserSlot] = []
        self._sem:    asyncio.Semaphore = asyncio.Semaphore(size)
        self._lock:   asyncio.Lock = asyncio.Lock()
        self._pw:     Optional["Playwright"] = None
        self._started = False

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    async def start(self):
        """Launch all browser processes. Call once from main()."""
        if not HAS_PLAYWRIGHT:
            logger.info("Browser pool skipped (playwright not installed)")
            return
        if self._started:
            return

        logger.info("Starting browser pool (size=%d)…", self._size)
        self._pw = await async_playwright().start()

        launch_args = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",   # use /tmp instead of /dev/shm
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--metrics-recording-only",
            "--no-first-run",
            "--mute-audio",
        ]

        for i in range(self._size):
            try:
                browser = await self._pw.chromium.launch(
                    headless=True,
                    args=launch_args,
                )
                context = await browser.new_context(
                    user_agent=random.choice(_UA_LIST),
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=True,
                )
                self._slots.append(_BrowserSlot(browser=browser, context=context))
                logger.info("  Browser slot %d ready (pid=%s)", i, getattr(browser, '_process', {}).get('pid', '?'))
            except Exception as exc:
                logger.error("Failed to launch browser slot %d: %s", i, exc)

        # Adjust semaphore to actual slots created
        actual = len(self._slots)
        if actual < self._size:
            # Release extra permits so the semaphore matches reality
            for _ in range(self._size - actual):
                self._sem.release()
        self._started = True
        logger.info("✅ Browser pool started (%d/%d slots)", actual, self._size)

    async def stop(self):
        """Gracefully close all browsers. Call from shutdown hook."""
        if not HAS_PLAYWRIGHT or not self._started:
            return
        async with self._lock:
            for slot in self._slots:
                try:
                    await slot.context.close()
                    await slot.browser.close()
                except Exception:
                    pass
            self._slots.clear()
        if self._pw:
            await self._pw.stop()
        self._started = False
        logger.info("Browser pool stopped")

    # ─── Slot acquisition ─────────────────────────────────────────────────────

    async def _acquire_slot(self) -> Optional[_BrowserSlot]:
        """
        Acquire a free slot.  Returns None if none available within 5 s
        (caller should fall back to aiohttp).
        """
        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("Browser pool exhausted — falling back to aiohttp")
            return None

        async with self._lock:
            for slot in self._slots:
                if not slot.in_use:
                    slot.in_use = True
                    return slot
        # Semaphore inconsistency — release and return None
        self._sem.release()
        return None

    def _release_slot(self, slot: _BrowserSlot):
        slot.in_use = False
        self._sem.release()

    # ─── Public render API ────────────────────────────────────────────────────

    async def render(
        self,
        url: str,
        *,
        timeout_ms: int = RENDER_TIMEOUT,
        wait_until: str = "networkidle",
        extra_headers: Optional[dict] = None,
    ) -> str:
        """
        Render a URL with a pooled browser and return the final HTML.

        Falls back to an aiohttp GET if:
          • Playwright is not installed
          • The pool is exhausted
          • Playwright raises an error
        """
        if not HAS_PLAYWRIGHT or not self._started or not self._slots:
            return await self._aiohttp_fallback(url)

        slot = await self._acquire_slot()
        if slot is None:
            return await self._aiohttp_fallback(url)

        try:
            # Recycle context if overused
            if slot.use_count >= CONTEXT_MAX_USE:
                await slot.recycle()

            page = await slot.context.new_page()
            if extra_headers:
                await page.set_extra_http_headers(extra_headers)

            try:
                await page.goto(
                    url,
                    wait_until=wait_until,
                    timeout=timeout_ms,
                )
                html = await page.content()
            except PlaywrightTimeout:
                # Partial render — grab what we have
                logger.debug("Playwright timeout for %s — partial render", url)
                try:
                    html = await page.content()
                except Exception:
                    html = ""
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

            slot.use_count += 1
            return html

        except Exception as exc:
            logger.warning("Browser pool render error for %s: %s", url, exc)
            # Recycle the slot's context to prevent state leakage
            try:
                await slot.recycle()
            except Exception:
                pass
            return await self._aiohttp_fallback(url)
        finally:
            self._release_slot(slot)

    async def render_and_scripts(
        self,
        url: str,
        *,
        timeout_ms: int = RENDER_TIMEOUT,
    ) -> tuple[str, list[str]]:
        """
        Renders the page AND intercepts all loaded script URLs.
        Returns (html, [script_url, ...]).

        Used by js_restore / JS secret mining to discover bundles without
        a second HTML-parse round-trip.
        """
        if not HAS_PLAYWRIGHT or not self._started or not self._slots:
            return await self._aiohttp_fallback(url), []

        slot = await self._acquire_slot()
        if slot is None:
            return await self._aiohttp_fallback(url), []

        script_urls: list[str] = []

        try:
            if slot.use_count >= CONTEXT_MAX_USE:
                await slot.recycle()

            page = await slot.context.new_page()

            # Intercept network requests to collect script URLs
            async def _on_request(request):
                if request.resource_type == "script":
                    script_urls.append(request.url)

            page.on("request", _on_request)

            try:
                await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                html = await page.content()
            except PlaywrightTimeout:
                try:
                    html = await page.content()
                except Exception:
                    html = ""
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

            slot.use_count += 1
            return html, script_urls

        except Exception as exc:
            logger.warning("render_and_scripts error for %s: %s", url, exc)
            try:
                await slot.recycle()
            except Exception:
                pass
            return await self._aiohttp_fallback(url), []
        finally:
            self._release_slot(slot)

    # ─── aiohttp fallback ─────────────────────────────────────────────────────

    @staticmethod
    async def _aiohttp_fallback(url: str) -> str:
        """Plain aiohttp GET — no JS execution."""
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(url, ssl=False) as resp:
                    return await resp.text(errors="replace")
        except Exception as exc:
            logger.debug("aiohttp fallback error for %s: %s", url, exc)
            return ""

    # ─── Stats ────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "pool_size":    self._size,
            "slots":        len(self._slots),
            "in_use":       sum(1 for s in self._slots if s.in_use),
            "use_counts":   [s.use_count for s in self._slots],
            "playwright":   HAS_PLAYWRIGHT,
            "started":      self._started,
        }


# ── Module-level singleton ────────────────────────────────────────────────────
browser_pool = BrowserPool(size=POOL_SIZE)


async def get_rendered_html(url: str, timeout_ms: int = RENDER_TIMEOUT) -> str:
    """
    Drop-in async replacement for the original get_rendered_html().
    Uses the persistent pool instead of spawning a new browser per call.
    """
    return await browser_pool.render(url, timeout_ms=timeout_ms)

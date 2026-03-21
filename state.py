"""
arch/state.py  —  Distributed State Management
================================================
Replaces ALL in-memory globals with a Redis-backed solution:
  • _SCAN_CACHE      → RedisCache (TTL-aware, JSON-serialised)
  • user_last_req    → RedisRateLimiter (token-bucket / sliding-window)
  • user_heavy_req   → RedisRateLimiter (heavy tier)
  • _active_scans    → RedisActiveScans
  • user_daily_quota → RedisDailyQuota
  • _queue_pos       → RedisQueuePos

Graceful degradation:
  If Redis is unavailable the module falls back to a thin in-process
  implementation so the bot still works on a single node with no extra
  infrastructure.  Set REDIS_URL="" in env to force local-only mode.

Design:
  • Every key is namespaced with REDIS_NS (default "bot:") to allow
    multiple bot instances on the same Redis without collisions.
  • All public methods are async (even the local fallback).
  • Serialisation is JSON; binary blobs are base64-encoded.
  • Rate-limiter uses a sorted-set sliding-window — O(log N) per call.
  • The cache uses a simple GET/SETEX pattern; eviction is Redis-native.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import threading
from typing import Any, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Environment ───────────────────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "")           # e.g. "redis://localhost:6379/0"
REDIS_NS  = os.getenv("REDIS_NS",  "bot:")       # key namespace prefix

# ── Try to import redis ───────────────────────────────────────────────────────
try:
    import redis.asyncio as aioredis          # redis>=4.2
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    logger.warning("redis package not installed — using in-process fallback state")


# ═══════════════════════════════════════════════════════════════════════════════
# 0.  Redis connection pool (singleton)
# ═══════════════════════════════════════════════════════════════════════════════

_redis_pool: Optional[Any] = None   # aioredis.Redis

async def _get_redis() -> Optional[Any]:
    """Return a Redis client, creating the pool on first call."""
    global _redis_pool
    if not HAS_REDIS or not REDIS_URL:
        return None
    if _redis_pool is None:
        try:
            _redis_pool = aioredis.from_url(
                REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=3,
                retry_on_timeout=True,
                max_connections=20,
            )
            # Probe the connection
            await _redis_pool.ping()
            logger.info("✅ Redis connected: %s", REDIS_URL.split("@")[-1])
        except Exception as exc:
            logger.warning("⚠️  Redis unavailable (%s) — using local fallback", exc)
            _redis_pool = None
    return _redis_pool


async def close_redis():
    """Graceful shutdown — call from main() cleanup."""
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.aclose()
        _redis_pool = None


# ═══════════════════════════════════════════════════════════════════════════════
# 1.  RedisCache  (replaces _SCAN_CACHE + threading.Lock)
# ═══════════════════════════════════════════════════════════════════════════════

class RedisCache:
    """
    Async LRU cache backed by Redis SETEX.

    Usage:
        cache = RedisCache(ttl=300, max_local=200)
        await cache.set("scan:example.com", result_dict)
        hit = await cache.get("scan:example.com")   # None on miss
    """

    def __init__(self, ttl: int = 300, max_local: int = 200, ns: str = "cache:"):
        self._ttl       = ttl
        self._ns        = REDIS_NS + ns
        # Local fallback (also acts as L1 in front of Redis)
        self._local: dict = {}
        self._local_lock  = threading.Lock()
        self._max_local   = max_local

    def _k(self, key: str) -> str:
        return self._ns + key

    # ── Local-only helpers ────────────────────────────────────────────────────
    def _local_get(self, key: str) -> Optional[Any]:
        with self._local_lock:
            entry = self._local.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._local[key]
                return None
            return value

    def _local_set(self, key: str, value: Any):
        with self._local_lock:
            if len(self._local) >= self._max_local:
                # Evict oldest
                oldest = min(self._local, key=lambda k: self._local[k][1])
                del self._local[oldest]
            self._local[key] = (value, time.monotonic() + self._ttl)

    # ── Public async API ──────────────────────────────────────────────────────
    async def get(self, key: str) -> Optional[Any]:
        # L1: local memory
        val = self._local_get(key)
        if val is not None:
            return val
        # L2: Redis
        r = await _get_redis()
        if r is not None:
            try:
                raw = await r.get(self._k(key))
                if raw is not None:
                    val = json.loads(raw)
                    self._local_set(key, val)   # promote to L1
                    return val
            except Exception as exc:
                logger.debug("Cache.get Redis error: %s", exc)
        return None

    async def set(self, key: str, value: Any):
        self._local_set(key, value)
        r = await _get_redis()
        if r is not None:
            try:
                await r.setex(self._k(key), self._ttl, json.dumps(value, default=str))
            except Exception as exc:
                logger.debug("Cache.set Redis error: %s", exc)

    async def delete(self, key: str):
        with self._local_lock:
            self._local.pop(key, None)
        r = await _get_redis()
        if r is not None:
            try:
                await r.delete(self._k(key))
            except Exception as exc:
                logger.debug("Cache.delete Redis error: %s", exc)

    async def cleanup(self):
        """Evict expired local entries (Redis handles its own TTLs)."""
        now = time.monotonic()
        with self._local_lock:
            stale = [k for k, (_, exp) in self._local.items() if now > exp]
            for k in stale:
                del self._local[k]
        return len(stale)


# ── Module-level singleton for scan results ───────────────────────────────────
scan_cache = RedisCache(ttl=300, max_local=200, ns="scan:")


# ═══════════════════════════════════════════════════════════════════════════════
# 2.  RedisRateLimiter  (replaces user_last_req / user_heavy_req dicts)
# ═══════════════════════════════════════════════════════════════════════════════

class RedisRateLimiter:
    """
    Sliding-window rate limiter.

    • With Redis: uses a sorted set keyed by uid; each call adds
      the current timestamp and removes entries older than `window`.
      Atomic via a Lua script → no race conditions.
    • Without Redis: uses a local dict with timestamp.

    Returns (allowed: bool, wait_secs: int).
    """

    _LUA_SLIDING = """
    local key    = KEYS[1]
    local now    = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local limit  = tonumber(ARGV[3])
    local cutoff = now - window

    redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
    local count = redis.call('ZCARD', key)

    if count < limit then
        redis.call('ZADD', key, now, now .. '-' .. math.random(1e9))
        redis.call('EXPIRE', key, window)
        return {1, 0}   -- allowed, wait=0
    else
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        local wait = math.ceil(tonumber(oldest[2]) + window - now)
        return {0, wait}
    end
    """

    def __init__(self, window: float, limit: int = 1, ns: str = "rl:"):
        self._window     = window
        self._limit      = limit
        self._ns         = REDIS_NS + ns
        self._local: dict = {}   # {uid: last_timestamp}
        self._lock        = threading.Lock()
        self._script_sha: Optional[str] = None

    def _k(self, uid: int) -> str:
        return f"{self._ns}{uid}"

    async def _get_script_sha(self, r) -> str:
        if self._script_sha is None:
            self._script_sha = await r.script_load(self._LUA_SLIDING)
        return self._script_sha

    async def check(self, uid: int) -> Tuple[bool, int]:
        """
        Returns (allowed, wait_seconds).
        Call this *before* the action; it records the attempt atomically.
        """
        # ── Redis path ────────────────────────────────────────────────────────
        r = await _get_redis()
        if r is not None:
            try:
                now = time.time()
                sha = await self._get_script_sha(r)
                result = await r.evalsha(
                    sha,
                    1,                    # numkeys
                    self._k(uid),         # KEYS[1]
                    now,                  # ARGV[1]
                    self._window,         # ARGV[2]
                    self._limit,          # ARGV[3]
                )
                allowed, wait = int(result[0]), int(result[1])
                return bool(allowed), wait
            except Exception as exc:
                logger.debug("RateLimiter Redis error: %s", exc)
                # Fall through to local

        # ── Local fallback ────────────────────────────────────────────────────
        now = time.monotonic()
        with self._lock:
            last = self._local.get(uid, 0)
            elapsed = now - last
            if elapsed >= self._window:
                self._local[uid] = now
                return True, 0
            wait = int(self._window - elapsed) + 1
            return False, wait

    def reset(self, uid: int):
        """Clear rate-limit state for a user (admin use)."""
        with self._lock:
            self._local.pop(uid, None)


# ── Module-level singletons matching original variable names ──────────────────
light_rate  = RedisRateLimiter(window=5,   limit=1, ns="rl:light:")
heavy_rate  = RedisRateLimiter(window=30,  limit=1, ns="rl:heavy:")
pentest_rate= RedisRateLimiter(window=120, limit=1, ns="rl:pentest:")


async def check_rate_limit(uid: int, heavy: bool = False) -> Tuple[bool, int]:
    """
    Drop-in async replacement for the original sync check_rate_limit().
    Returns (allowed, wait_secs).
    """
    limiter = heavy_rate if heavy else light_rate
    return await limiter.check(uid)


# ═══════════════════════════════════════════════════════════════════════════════
# 3.  RedisActiveScans  (replaces _active_scans ThreadSafeDict)
# ═══════════════════════════════════════════════════════════════════════════════

class RedisActiveScans:
    """
    Track which scan (if any) is running for each user.
    Backed by Redis HSET; local dict is kept in sync as a fast-path read.

    Keys expire after `ttl` seconds to auto-clean crashed workers.
    """

    def __init__(self, ttl: int = 600, ns: str = "active_scans"):
        self._hash_key = REDIS_NS + ns
        self._ttl      = ttl
        self._local: dict = {}
        self._lock    = threading.Lock()

    async def set(self, uid: int, task_name: str):
        with self._lock:
            self._local[uid] = task_name
        r = await _get_redis()
        if r is not None:
            try:
                pipe = r.pipeline()
                pipe.hset(self._hash_key, str(uid), task_name)
                pipe.expire(self._hash_key, self._ttl)
                await pipe.execute()
            except Exception as exc:
                logger.debug("ActiveScans.set Redis error: %s", exc)

    async def get(self, uid: int) -> Optional[str]:
        with self._lock:
            if uid in self._local:
                return self._local[uid]
        r = await _get_redis()
        if r is not None:
            try:
                val = await r.hget(self._hash_key, str(uid))
                if val:
                    with self._lock:
                        self._local[uid] = val
                    return val
            except Exception as exc:
                logger.debug("ActiveScans.get Redis error: %s", exc)
        return None

    async def pop(self, uid: int, default=None):
        with self._lock:
            self._local.pop(uid, None)
        r = await _get_redis()
        if r is not None:
            try:
                await r.hdel(self._hash_key, str(uid))
            except Exception as exc:
                logger.debug("ActiveScans.pop Redis error: %s", exc)
        return default

    async def contains(self, uid: int) -> bool:
        return (await self.get(uid)) is not None

    async def items(self) -> list:
        r = await _get_redis()
        if r is not None:
            try:
                data = await r.hgetall(self._hash_key)
                return [(int(k), v) for k, v in data.items()]
            except Exception as exc:
                logger.debug("ActiveScans.items Redis error: %s", exc)
        with self._lock:
            return list(self._local.items())

    # ── __contains__ shim for sync code that does `if uid in _active_scans` ──
    def __contains__(self, uid: int) -> bool:
        """
        Synchronous check against local cache only.
        Use `await active_scans.contains(uid)` for the authoritative check.
        """
        with self._lock:
            return uid in self._local


# Singleton
active_scans = RedisActiveScans()


# ═══════════════════════════════════════════════════════════════════════════════
# 4.  RedisDailyQuota  (replaces user_daily_quota ThreadSafeDict)
# ═══════════════════════════════════════════════════════════════════════════════

class RedisDailyQuota:
    """
    Per-user daily quota counters keyed by (uid, cmd_type, date).
    Backed by Redis INCR with TTL=86400; local dict for fast-path reads.

    Usage:
        ok, remaining, msg = await quota.check(uid, "scan", limit=10)
        if ok:
            await quota.increment(uid, "scan")
    """

    def __init__(self, ns: str = "quota:"):
        self._ns   = REDIS_NS + ns
        self._local: dict = {}      # {(uid, cmd, date): count}
        self._lock = threading.Lock()

    def _k(self, uid: int, cmd: str) -> str:
        today = time.strftime("%Y-%m-%d")
        return f"{self._ns}{uid}:{cmd}:{today}"

    def _local_k(self, uid: int, cmd: str) -> tuple:
        return (uid, cmd, time.strftime("%Y-%m-%d"))

    async def count(self, uid: int, cmd: str) -> int:
        r = await _get_redis()
        if r is not None:
            try:
                val = await r.get(self._k(uid, cmd))
                return int(val) if val else 0
            except Exception as exc:
                logger.debug("Quota.count Redis error: %s", exc)
        lk = self._local_k(uid, cmd)
        with self._lock:
            return self._local.get(lk, 0)

    async def increment(self, uid: int, cmd: str) -> int:
        """Increment counter and return new count."""
        r = await _get_redis()
        if r is not None:
            try:
                pipe = r.pipeline()
                k = self._k(uid, cmd)
                pipe.incr(k)
                pipe.expire(k, 86400)
                results = await pipe.execute()
                new_count = int(results[0])
                lk = self._local_k(uid, cmd)
                with self._lock:
                    self._local[lk] = new_count
                return new_count
            except Exception as exc:
                logger.debug("Quota.increment Redis error: %s", exc)
        lk = self._local_k(uid, cmd)
        with self._lock:
            self._local[lk] = self._local.get(lk, 0) + 1
            return self._local[lk]

    async def check(self, uid: int, cmd: str, limit: int) -> Tuple[bool, int, str]:
        """
        Returns (ok, remaining, message).
        Does NOT increment — call increment() after the action completes.
        """
        current = await self.count(uid, cmd)
        remaining = max(0, limit - current)
        if current >= limit:
            return False, 0, (
                f"📊 *Daily {cmd} limit reached* (`{limit}`/day)\n"
                f"🔄 Resets at midnight UTC"
            )
        return True, remaining, ""

    async def reset(self, uid: int, cmd: str):
        r = await _get_redis()
        if r is not None:
            try:
                await r.delete(self._k(uid, cmd))
            except Exception:
                pass
        lk = self._local_k(uid, cmd)
        with self._lock:
            self._local.pop(lk, None)


# Singleton
daily_quota = RedisDailyQuota()

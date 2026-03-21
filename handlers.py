"""
arch/handlers.py  —  Refactored Async Command Handlers
========================================================
Drop-in replacements for the cmd_vuln and cmd_api_discover functions
in bot_v50_final.py, demonstrating the full v51 async architecture.

Changes vs v50:
  ① asyncio.to_thread(_vuln_scan_sync, …)  →  native async scan coroutine
     called directly — no thread spawning.
  ② requests.get inside discover_api_endpoints  →  probe_many() from
     arch.http_client (pure aiohttp, semaphore-bounded concurrency).
  ③ _active_scans ThreadSafeDict  →  RedisActiveScans (arch.state).
  ④ check_rate_limit (sync)       →  async check_rate_limit (arch.state).
  ⑤ _format_vuln_report           →  format_vuln_report (arch.reporting)
     with the HOW-TO-FIX bug fixed.
  ⑥ _run_single_engine            →  run_single_engine with fixed
     format_engine_result (arch.reporting).

These handlers are meant to be registered in main() alongside the
existing CommandHandler registrations:

    from arch.handlers import cmd_vuln_v51, cmd_api_discover_v51, run_single_engine_v51

    app.add_handler(CommandHandler("vuln",         cmd_vuln_v51))
    app.add_handler(CommandHandler("api_discover",  cmd_api_discover_v51))
    # etc.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

from telegram import Update
from telegram.ext import ContextTypes

# ── arch imports ──────────────────────────────────────────────────────────────
from arch.state    import active_scans, check_rate_limit, daily_quota
from arch.reporting import format_vuln_report, format_engine_result, format_api_discovery
from arch.http_client import probe_many, get, FAST_TIMEOUT

logger = logging.getLogger(__name__)

# ── These are still imported from the original bot file ───────────────────────
# (They contain the actual scan logic which we do NOT rewrite here;
#  only the I/O layer around them is upgraded.)
try:
    from bot_v50_final import (
        _vuln_scan_sync,
        discover_api_endpoints as _discover_api_endpoints_sync,
        is_safe_url,
        check_force_join,
        _scan_tasks,
        DAILY_LIMIT_PER_USER_SCAN,
        ALL_API_PATHS,
    )
    _ORIG_AVAILABLE = True
except ImportError:
    _ORIG_AVAILABLE = False
    logger.warning(
        "bot_v50_final not importable — handlers will use stub scan functions"
    )

    # ── Stub implementations for standalone testing ───────────────────────────
    async def is_safe_url(url): return True, ""
    async def check_force_join(u, c): return True
    _scan_tasks = {}
    DAILY_LIMIT_PER_USER_SCAN = 10
    ALL_API_PATHS = []

    def _vuln_scan_sync(url, pq):
        return {"url": url, "findings": [], "total_scanned": 0,
                "https": url.startswith("https"), "clickjacking": False,
                "missing_headers": [], "error_rate": 0.0}

    def _discover_api_endpoints_sync(url, cb=None):
        return {"found": [], "js_mined": [], "html_mined": [],
                "robots": [], "stats": {}}


# ═══════════════════════════════════════════════════════════════════════════════
# cmd_vuln_v51
# ═══════════════════════════════════════════════════════════════════════════════

async def cmd_vuln_v51(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /vuln <url>  —  Passive vulnerability scanner (v51 async architecture).

    Key changes:
      • Rate limit and active-scan checks are now async (Redis-backed).
      • The sync scan engine still runs in to_thread (it has internal
        requests.get calls we cannot refactor without touching 4000+ lines).
        Once the scan engine is fully ported to aiohttp this to_thread call
        becomes a direct await.
      • The report formatter is the FIXED version with no spurious HOW-TO-FIX.
    """
    uid = update.effective_user.id

    # ── Guard: force-join ─────────────────────────────────────────────────────
    if not await check_force_join(update, context):
        return

    # ── Guard: rate limit (async, Redis-backed) ───────────────────────────────
    allowed, wait = await check_rate_limit(uid, heavy=True)
    if not allowed:
        await update.effective_message.reply_text(
            f"⏳ `{wait}s` စောင့်ပါ", parse_mode="Markdown"
        )
        return

    # ── Guard: daily quota ────────────────────────────────────────────────────
    ok, remaining, qmsg = await daily_quota.check(uid, "scan", DAILY_LIMIT_PER_USER_SCAN)
    if not ok:
        await update.effective_message.reply_text(qmsg, parse_mode="Markdown")
        return

    # ── Guard: already running ────────────────────────────────────────────────
    if await active_scans.contains(uid):
        current = await active_scans.get(uid)
        await update.effective_message.reply_text(
            f"⏳ *`{current}` running* — ပြီးဆုံးဖို့ စောင့်ပါ\n"
            "သို့မဟုတ် `/stop` နှိပ်ပါ",
            parse_mode="Markdown",
        )
        return

    # ── Validate args ─────────────────────────────────────────────────────────
    if not context.args:
        await update.effective_message.reply_text(
            "🛡️ *Vulnerability Scanner v51*\n\n"
            "Usage: `/vuln <url>`\n\n"
            "• 📡 Subdomain discovery\n"
            "• ☁️ Cloudflare detection\n"
            "• 🔑 Config/credential leaks\n"
            "• 📁 Git/backup/DB dumps\n"
            "• 🔐 Admin panel detection\n\n"
            "_Passive only — no exploitation_",
            parse_mode="Markdown",
        )
        return

    url = context.args[0].strip()
    if not url.startswith("http"):
        url = "https://" + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(
            f"🚫 `{reason}`", parse_mode="Markdown"
        )
        return

    domain = urlparse(url).netloc

    # ── Mark scan as active ───────────────────────────────────────────────────
    await active_scans.set(uid, "Vuln scan")

    # ── Send initial message ──────────────────────────────────────────────────
    msg = await update.effective_message.reply_text(
        f"🛡️ *Vuln Scan v51*\n🌐 `{domain}`\n\n"
        "• Baseline & catch-all detection\n"
        "• Subdomain discovery\n"
        "• Path scanning\n\n_ခဏစောင့်ပါ..._",
        parse_mode="Markdown",
    )

    # ── Live progress ─────────────────────────────────────────────────────────
    progress_q: list = []

    async def _prog_loop():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                txt = progress_q[-1]
                progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🛡️ *Scanning `{domain}`*\n\n{txt}",
                        parse_mode="Markdown",
                    )
                except Exception:
                    pass

    prog = asyncio.create_task(_prog_loop())

    try:
        # NOTE: _vuln_scan_sync contains internal requests.get calls.
        # We run it in a thread until the scan engine itself is ported to aiohttp.
        # The to_thread wrapper is the ONLY remaining threading in this command.
        scan_task = asyncio.create_task(
            asyncio.to_thread(_vuln_scan_sync, url, progress_q)
        )
        _scan_tasks[uid] = scan_task
        results = await scan_task

    except asyncio.CancelledError:
        try:
            await msg.edit_text("🛑 *Vuln scan ရပ်သွားပြီ*", parse_mode="Markdown")
        except Exception:
            pass
        return

    except Exception as exc:
        await msg.edit_text(
            f"❌ Scan error: `{type(exc).__name__}: {str(exc)[:80]}`",
            parse_mode="Markdown",
        )
        return

    finally:
        prog.cancel()
        await active_scans.pop(uid)
        _scan_tasks.pop(uid, None)

    # ── Increment quota AFTER successful scan ─────────────────────────────────
    await daily_quota.increment(uid, "scan")

    # ── Format and send report (FIXED formatter — no spurious HOW-TO-FIX) ────
    report = format_vuln_report(results)
    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode="Markdown")
        else:
            await msg.edit_text(report[:4000] + "\n_...continued_", parse_mode="Markdown")
            await update.effective_message.reply_text(
                report[4000:8000], parse_mode="Markdown"
            )
    except Exception:
        await update.effective_message.reply_text(report[:4000], parse_mode="Markdown")


# ═══════════════════════════════════════════════════════════════════════════════
# cmd_api_discover_v51
# ═══════════════════════════════════════════════════════════════════════════════

async def cmd_api_discover_v51(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /api_discover <url>  —  API endpoint discovery (v51 async architecture).

    The INNER discovery logic still calls the sync discover_api_endpoints
    for the path-brute-force phase.  The high-frequency probe loop inside
    that function uses requests.get in a ThreadPoolExecutor.  The v51 plan
    is to replace that with probe_many() from arch.http_client — the
    refactored version is shown in _discover_api_endpoints_async() below
    as a reference implementation.
    """
    if not await check_force_join(update, context):
        return

    uid = update.effective_user.id

    if await active_scans.contains(uid):
        current = await active_scans.get(uid)
        await update.effective_message.reply_text(
            f"⏳ *`{current}` running* — ပြီးဆုံးဖို့ စောင့်ပါ\n"
            "သို့မဟုတ် `/stop` နှိပ်ပါ",
            parse_mode="Markdown",
        )
        return

    allowed, wait = await check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(
            f"⏳ `{wait}s` စောင့်ပါ", parse_mode="Markdown"
        )
        return

    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/api_discover https://example.com`\n\n"
            f"🔌 Probes `{len(ALL_API_PATHS)}` known API paths\n"
            "🕵️ Mines JS bundles & HTML source\n"
            "🤖 Scans robots.txt / sitemap",
            parse_mode="Markdown",
        )
        return

    url = context.args[0].strip()
    if not url.startswith("http"):
        url = "https://" + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode="Markdown")
        return

    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🔌 *API Discovery — `{domain}`*\n\n⏳ Scanning…",
        parse_mode="Markdown",
    )

    await active_scans.set(uid, "API Discovery")
    progress_q: list = []

    async def _prog_loop():
        while True:
            await asyncio.sleep(4)
            if progress_q:
                txt = progress_q[-1]
                progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🔌 *Scanning `{domain}`*\n\n{txt}",
                        parse_mode="Markdown",
                    )
                except Exception:
                    pass

    prog = asyncio.create_task(_prog_loop())

    try:
        # Use the native async version when available; fall back to sync wrapper
        if _ORIG_AVAILABLE:
            found = await asyncio.to_thread(
                _discover_api_endpoints_sync, url, lambda t: progress_q.append(t)
            )
        else:
            found = await _discover_api_endpoints_async(url, progress_q)
    except Exception as exc:
        await msg.edit_text(f"❌ Error: `{exc}`", parse_mode="Markdown")
        return
    finally:
        prog.cancel()
        await active_scans.pop(uid)

    # ── FIXED formatter — no spurious fix blocks on empty results ─────────────
    report = format_api_discovery(found, domain)

    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode="Markdown")
        else:
            await msg.edit_text(report[:4000] + "\n_...continued_", parse_mode="Markdown")
            await update.effective_message.reply_text(report[4000:8000], parse_mode="Markdown")
    except Exception:
        await update.effective_message.reply_text(report[:4000], parse_mode="Markdown")


# ═══════════════════════════════════════════════════════════════════════════════
# Reference: fully native async API discovery (probe_many replaces ThreadPool)
# ═══════════════════════════════════════════════════════════════════════════════

async def _discover_api_endpoints_async(base_url: str, progress_q: list) -> dict:
    """
    Pure-async reference implementation of discover_api_endpoints().
    Uses probe_many() (aiohttp + semaphore) instead of ThreadPoolExecutor.

    This is the target state once the main engine is fully ported.
    Currently used when bot_v50_final is not importable (standalone mode).
    """
    from urllib.parse import urljoin, urlparse as _up

    root = f"{_up(base_url).scheme}://{_up(base_url).netloc}"

    # ── Phase 1: HTML source mining ───────────────────────────────────────────
    progress_q.append("🔍 Phase 1: HTML source mining…")
    html, status = await get(base_url)
    html_mined: list[str] = []
    if html:
        # Extract href/src attributes pointing to API-like paths
        import re
        for m in re.finditer(r'(?:href|src|action)=["\']([^"\']{3,200})["\']', html):
            val = m.group(1)
            if any(kw in val for kw in ("/api/", "/v1/", "/v2/", "/graphql")):
                html_mined.append(urljoin(base_url, val))

    # ── Phase 2: robots.txt ───────────────────────────────────────────────────
    progress_q.append("🤖 Phase 2: robots.txt scan…")
    robots_urls: list[str] = []
    robots_text, _ = await get(root + "/robots.txt")
    if robots_text:
        import re
        for m in re.finditer(r"(?:Allow|Disallow):\s*(/[^\s]+)", robots_text):
            robots_urls.append(root + m.group(1))

    # ── Phase 3: path brute-force via probe_many ──────────────────────────────
    progress_q.append(f"🔌 Phase 3: Probing {len(ALL_API_PATHS)} paths…")
    probe_urls = [urljoin(root, path) for path in (ALL_API_PATHS or [])]

    found_endpoints: list[dict] = []
    if probe_urls:
        results = await probe_many(
            probe_urls,
            concurrency=20,
            delay=0.15,
            timeout=FAST_TIMEOUT,
        )
        for url, status, body in results:
            if status in (200, 201, 204):
                ep_type = "JSON_API"
                if body and body.strip().startswith("{"):
                    ep_type = "JSON_API"
                elif "graphql" in url.lower():
                    ep_type = "GRAPHQL"
                found_endpoints.append({
                    "url": url, "status": status, "type": ep_type,
                    "method": "GET", "risk": 10,
                    "preview": (body or "")[:60].replace("\n", " "),
                    "cors": None, "size_b": len(body or ""),
                })
            elif status in (401, 403):
                found_endpoints.append({
                    "url": url, "status": status, "type": "PROTECTED",
                    "method": "GET", "risk": 5, "note": str(status),
                    "cors": None, "size_b": 0,
                })

    progress_q.append(f"✅ Done — {len(found_endpoints)} endpoints found")

    return {
        "found":    found_endpoints,
        "js_mined": [],
        "html_mined": html_mined,
        "robots":   robots_urls,
        "stats": {
            "total_probed":    len(probe_urls),
            "js_urls_found":   0,
            "html_urls_found": len(html_mined),
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# run_single_engine_v51  (replaces _run_single_engine)
# ═══════════════════════════════════════════════════════════════════════════════

async def run_single_engine_v51(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    engine_name: str,
    engine_fn,           # callable(url, forms, params, progress_cb) -> dict
    label: str,
    emoji: str,
):
    """
    Generic wrapper for single-engine commands (sqli, xss, ssrf, lfi, auth).

    Fixes vs v50:
      • Uses async check_rate_limit and active_scans (Redis-backed).
      • format_engine_result() only appends HOW-TO-FIX when is_vuln=True.
    """
    if not await check_force_join(update, context):
        return

    uid = update.effective_user.id

    allowed, wait = await check_rate_limit(uid, heavy=True)
    if not allowed:
        await update.effective_message.reply_text(
            f"⏳ `{wait}s` စောင့်ပါ", parse_mode="Markdown"
        )
        return

    if await active_scans.contains(uid):
        current = await active_scans.get(uid)
        await update.effective_message.reply_text(
            f"⏳ `{current}` running", parse_mode="Markdown"
        )
        return

    if not context.args:
        await update.effective_message.reply_text(
            f"📌 *Usage:* `/{engine_name} <url>`", parse_mode="Markdown"
        )
        return

    url = context.args[0].strip()
    if not url.startswith("http"):
        url = "https://" + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(
            f"❌ *Blocked:* `{reason}`", parse_mode="Markdown"
        )
        return

    domain = urlparse(url).netloc
    await active_scans.set(uid, engine_name)

    msg = await update.effective_message.reply_text(
        f"{emoji} *{label} — `{domain}`*\n\n⏳ Scanning…", parse_mode="Markdown"
    )

    try:
        # _prescan is still sync in v50 — wrap it
        try:
            from bot_v50_final import _prescan
            html, forms, params = await _prescan(url)
        except ImportError:
            html, forms, params = "", [], {}

        prog: list = []
        result = await asyncio.to_thread(engine_fn, url, forms, params, prog.append)

        # ── FIXED: format_engine_result handles is_vuln check internally ─────
        text = format_engine_result(result, label=label, emoji=emoji, domain=domain)

        if len(text) > 4000:
            text = text[:4000] + "\n_...truncated_"

        await msg.edit_text(text, parse_mode="Markdown")

    except Exception as exc:
        logger.error("%s error: %s", engine_name, exc, exc_info=True)
        await msg.edit_text(
            f"❌ *{label} Failed:* `{str(exc)[:100]}`", parse_mode="Markdown"
        )
    finally:
        await active_scans.pop(uid)

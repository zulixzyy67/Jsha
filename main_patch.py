"""
arch/main_patch.py  —  main() Integration & Wiring Guide
==========================================================
This module shows exactly how to wire arch/* into the existing main()
function in bot_v50_final.py.  Copy the sections marked ① – ⑦ into
your bot file.

You do NOT need to rewrite the 24 000-line bot file all at once.
The strategy is:

  Phase A (this PR): Replace infrastructure (state, DB, HTTP, browser pool).
  Phase B          : Swap command handlers one at a time using run_single_engine_v51.
  Phase C          : Port _vuln_scan_sync internals to aiohttp (removes last to_thread).

Migration checklist
───────────────────
  [x]  arch/state.py        — Redis-backed rate-limit, cache, active-scans, quota
  [x]  arch/db.py           — aiosqlite ORM (replaces sqlite3 + run_in_executor)
  [x]  arch/http_client.py  — aiohttp session pool (replaces requests + ThreadPool)
  [x]  arch/browser_pool.py — persistent Playwright pool (replaces per-call launch)
  [x]  arch/js_parser.py    — tiered AST+bounded-regex parser (replaces bare regex)
  [x]  arch/reporting.py    — fixed formatters (HOW-TO-FIX bug resolved)
  [x]  arch/handlers.py     — async command handlers (replaces sync wrappers)
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal

logger = logging.getLogger(__name__)

# ── Arch imports ──────────────────────────────────────────────────────────────
from arch.state       import active_scans, scan_cache, close_redis
from arch.db          import AsyncDB
from arch.http_client import start_client, close_client
from arch.browser_pool import browser_pool
from arch.handlers    import (
    cmd_vuln_v51,
    cmd_api_discover_v51,
    run_single_engine_v51,
)
from arch.reporting import format_vuln_report, format_engine_result

# ── Bot config (from original) ────────────────────────────────────────────────
BOT_TOKEN  = os.getenv("BOT_TOKEN", "")
DATA_DIR   = os.getenv("DATA_DIR", "/app/data")
SQLITE_FILE= os.path.join(DATA_DIR, "bot_db.sqlite")
DB_FILE    = os.path.join(DATA_DIR, "bot_db.json")   # legacy JSON for migration


# ═══════════════════════════════════════════════════════════════════════════════
# ①  Async DB singleton (module-level — import this wherever DB is needed)
# ═══════════════════════════════════════════════════════════════════════════════
db = AsyncDB(SQLITE_FILE)


# ═══════════════════════════════════════════════════════════════════════════════
# ②  post_init hook — runs inside the event loop, before polling starts
# ═══════════════════════════════════════════════════════════════════════════════
async def post_init(application) -> None:
    """
    Called by PTB's Application.post_init.
    Replaces the manual asyncio.ensure_future() calls in the old main().
    """
    # ── Database ──────────────────────────────────────────────────────────────
    await db.init()
    await db.migrate_from_json(DB_FILE)
    logger.info("✅ AsyncDB ready")

    # ── HTTP session ──────────────────────────────────────────────────────────
    await start_client()
    logger.info("✅ aiohttp session pool ready")

    # ── Browser pool ──────────────────────────────────────────────────────────
    await browser_pool.start()
    logger.info("✅ Browser pool ready: %s", browser_pool.stats())

    # ── Periodic cache cleanup task ───────────────────────────────────────────
    async def _cleanup_loop():
        while True:
            await asyncio.sleep(300)
            evicted = await scan_cache.cleanup()
            if evicted:
                logger.debug("Scan cache cleanup: evicted %d entries", evicted)

    asyncio.create_task(_cleanup_loop(), name="cache_cleanup")

    # ── Log Redis connection state ────────────────────────────────────────────
    from arch.state import _get_redis
    r = await _get_redis()
    if r:
        logger.info("✅ Redis state backend connected")
    else:
        logger.info("⚠️  Redis unavailable — using in-process state fallback")


# ═══════════════════════════════════════════════════════════════════════════════
# ③  post_shutdown hook — graceful teardown
# ═══════════════════════════════════════════════════════════════════════════════
async def post_shutdown(application) -> None:
    """
    Called by PTB's Application.post_shutdown.
    Closes all long-lived resources cleanly.
    """
    await browser_pool.stop()
    await close_client()
    await close_redis()
    logger.info("✅ All resources shut down cleanly")


# ═══════════════════════════════════════════════════════════════════════════════
# ④  Async db_read / db_write shims (drop-in for old pattern)
# ═══════════════════════════════════════════════════════════════════════════════
async def db_read() -> dict:
    """Async replacement for the original db_read()."""
    return await db.load_full()


async def db_write(data: dict):
    """Async replacement for the original db_write()."""
    await db.save_full(data)


async def db_update(func):
    """Atomic read-modify-write shim."""
    full = await db.load_full()
    func(full)
    await db.save_full(full)
    return full


# ═══════════════════════════════════════════════════════════════════════════════
# ⑤  Async sqlite_get_user / sqlite_upsert_user / sqlite_is_banned shims
# ═══════════════════════════════════════════════════════════════════════════════
async def sqlite_get_user(uid: int):
    return await db.get_user(uid)

async def sqlite_upsert_user(uid: int, user: dict):
    await db.upsert_user(uid, user)

async def sqlite_is_banned(uid: int) -> bool:
    return await db.is_banned(uid)


# ═══════════════════════════════════════════════════════════════════════════════
# ⑥  Handler factories for single-engine commands
#     These produce the same coroutine signatures PTB expects.
# ═══════════════════════════════════════════════════════════════════════════════
def make_engine_handler(engine_name, engine_fn, label, emoji):
    """
    Factory that wraps run_single_engine_v51 into a PTB-compatible handler.

    Usage in main():
        app.add_handler(CommandHandler("sqlitest",
            make_engine_handler("sqlitest", _sqli_engine_sync, "SQLi Test", "💉")
        ))
    """
    async def handler(update, context):
        await run_single_engine_v51(
            update, context,
            engine_name=engine_name,
            engine_fn=engine_fn,
            label=label,
            emoji=emoji,
        )
    handler.__name__ = f"cmd_{engine_name}_v51"
    return handler


# ═══════════════════════════════════════════════════════════════════════════════
# ⑦  The patched main() — copy this over the existing main() in bot_v50_final.py
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    """
    v51 main() — replaces the original.

    Changes from v50:
      • HTTPXRequest replaced with default (PTB handles its own HTTP).
      • post_init / post_shutdown hooks replace manual loop.run_until_complete.
      • All cmd_vuln / cmd_api_discover / engine handlers swapped to v51.
      • db_lock removed (aiosqlite handles locking internally).
      • download_semaphore / scan_semaphore unchanged (still asyncio.Semaphore).
    """
    import os
    from telegram.ext import (
        Application, CommandHandler, CallbackQueryHandler,
        MessageHandler, filters,
    )

    if not BOT_TOKEN:
        raise SystemExit("❌ BOT_TOKEN not set")

    # ── Build application ─────────────────────────────────────────────────────
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    # ── Re-import engine functions from original file ─────────────────────────
    try:
        from bot_v50_final import (
            _sqli_engine_sync, _xss_engine_sync, _ssrf_engine_sync,
            _lfi_engine_sync, _auth_engine_sync,
            # All unchanged command handlers:
            cmd_start, cmd_help, cmd_status, cmd_history, cmd_mystats,
            cmd_stop, cmd_resume, cmd_dl, cmd_scan, cmd_recon,
            cmd_discover, cmd_api, cmd_monitor, cmd_screenshot,
            cmd_appassets, cmd_jwtattack, cmd_admin, cmd_ban, cmd_unban,
            cmd_userinfo, cmd_broadcast, cmd_allusers, cmd_setforcejoin,
            cmd_sys, cmd_adminset, cmd_botstats, cmd_tech_stack,
            cmd_api_fuzzer, cmd_password_leak_check, cmd_site_map,
            cmd_whois, cmd_whois_lookup, cmd_dns_enum, cmd_port_scan,
            cmd_ssl_check, cmd_headers_check, cmd_waf_detect, cmd_cors_check,
            cmd_dir_brute, cmd_subdomain_enum, cmd_cms_detect, cmd_speed_audit,
            cmd_graphql, cmd_js_restore, cmd_fixall, cmd_cloudcheck,
            cmd_paramfuzz, cmd_autopwn, cmd_api_unified,
            handle_app_upload,
        )
    except ImportError as exc:
        raise SystemExit(f"Cannot import from bot_v50_final: {exc}")

    # ── Unchanged handlers ────────────────────────────────────────────────────
    app.add_handler(CommandHandler("start",     cmd_start))
    app.add_handler(CommandHandler("help",      cmd_help))
    app.add_handler(CommandHandler("status",    cmd_status))
    app.add_handler(CommandHandler("history",   cmd_history))
    app.add_handler(CommandHandler("mystats",   cmd_mystats))
    app.add_handler(CommandHandler("stop",      cmd_stop))
    app.add_handler(CommandHandler("resume",    cmd_resume))
    app.add_handler(CommandHandler("dl",        cmd_dl))
    app.add_handler(CommandHandler("scan",      cmd_scan))
    app.add_handler(CommandHandler("recon",     cmd_recon))
    app.add_handler(CommandHandler("discover",  cmd_discover))
    app.add_handler(CommandHandler("monitor",   cmd_monitor))
    app.add_handler(CommandHandler("screenshot",cmd_screenshot))
    app.add_handler(CommandHandler("appassets", cmd_appassets))
    app.add_handler(CommandHandler("jwtattack", cmd_jwtattack))
    app.add_handler(CommandHandler("admin",     cmd_admin))
    app.add_handler(CommandHandler("ban",       cmd_ban))
    app.add_handler(CommandHandler("unban",     cmd_unban))
    app.add_handler(CommandHandler("userinfo",  cmd_userinfo))
    app.add_handler(CommandHandler("broadcast", cmd_broadcast))
    app.add_handler(CommandHandler("allusers",  cmd_allusers))
    app.add_handler(CommandHandler("setforcejoin", cmd_setforcejoin))
    app.add_handler(CommandHandler("sys",       cmd_sys))
    app.add_handler(CommandHandler("adminset",  cmd_adminset))
    app.add_handler(CommandHandler("botstats",  cmd_botstats))
    app.add_handler(CommandHandler("tech_stack",          cmd_tech_stack))
    app.add_handler(CommandHandler("api_fuzzer",          cmd_api_fuzzer))
    app.add_handler(CommandHandler("password_leak_check", cmd_password_leak_check))
    app.add_handler(CommandHandler("site_map",            cmd_site_map))
    app.add_handler(CommandHandler("whois",               cmd_whois))
    app.add_handler(CommandHandler("whois_lookup",        cmd_whois_lookup))
    app.add_handler(CommandHandler("dns_enum",            cmd_dns_enum))
    app.add_handler(CommandHandler("port_scan",           cmd_port_scan))
    app.add_handler(CommandHandler("ssl_check",           cmd_ssl_check))
    app.add_handler(CommandHandler("headers_check",       cmd_headers_check))
    app.add_handler(CommandHandler("waf_detect",          cmd_waf_detect))
    app.add_handler(CommandHandler("cors_check",          cmd_cors_check))
    app.add_handler(CommandHandler("dir_brute",           cmd_dir_brute))
    app.add_handler(CommandHandler("subdomain_enum",      cmd_subdomain_enum))
    app.add_handler(CommandHandler("cms_detect",          cmd_cms_detect))
    app.add_handler(CommandHandler("speed_audit",         cmd_speed_audit))
    app.add_handler(CommandHandler("graphql",             cmd_graphql))
    app.add_handler(CommandHandler("js_restore",          cmd_js_restore))
    app.add_handler(CommandHandler("fixall",              cmd_fixall))
    app.add_handler(CommandHandler("cloudcheck",          cmd_cloudcheck))
    app.add_handler(CommandHandler("paramfuzz",           cmd_paramfuzz))
    app.add_handler(CommandHandler("autopwn",             cmd_autopwn))
    app.add_handler(CommandHandler("api",                 cmd_api_unified))

    # ── v51 UPGRADED handlers (swapped from v50 equivalents) ─────────────────
    app.add_handler(CommandHandler("vuln",        cmd_vuln_v51))          # ← FIXED
    app.add_handler(CommandHandler("api_discover",cmd_api_discover_v51))  # ← FIXED

    # Single-engine handlers now use the fixed formatter via factory
    app.add_handler(CommandHandler("sqlitest",
        make_engine_handler("sqlitest", _sqli_engine_sync, "SQL Injection Test", "💉")))
    app.add_handler(CommandHandler("xsstest",
        make_engine_handler("xsstest", _xss_engine_sync, "XSS Test", "🕷️")))
    app.add_handler(CommandHandler("ssrf",
        make_engine_handler("ssrf", _ssrf_engine_sync, "SSRF + Open Redirect", "🔁")))
    app.add_handler(CommandHandler("lfi",
        make_engine_handler("lfi", _lfi_engine_sync, "LFI / Path Traversal", "📁")))
    app.add_handler(CommandHandler("auth",
        make_engine_handler("auth", _auth_engine_sync, "Auth Weakness Test", "🔐")))

    # ── Document upload ───────────────────────────────────────────────────────
    app.add_handler(MessageHandler(filters.Document.ALL, handle_app_upload))

    # ── Run ───────────────────────────────────────────────────────────────────
    logger.info("🚀 Bot v51 starting (polling)…")
    app.run_polling(
        allowed_updates=["message", "callback_query"],
        close_loop=False,
    )


if __name__ == "__main__":
    main()

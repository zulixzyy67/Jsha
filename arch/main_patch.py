#!/usr/bin/env python3
"""
main_patch.py — Bot v51 Entry Point
ဖိုင်တွေ root မှာ ရှိလည်း အလုပ်လုပ်အောင် ပြင်ထားတယ်
"""

from __future__ import annotations

import sys
import os

# ── Path fix: ဖိုင်တွေ root မှာ ရှိရင် arch/ အောက်မှာ ရှိရင် နှစ်မျိုးလုံး အလုပ်လုပ်မယ် ──
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT   = os.path.dirname(_THIS_DIR)

# root ထည့်ပါ
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import asyncio
import logging

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ── Imports — arch/ ထဲမှာ ရှိရင် arch.xxx, root မှာ ရှိရင် xxx တိုက်ရိုက် ──
try:
    from arch.state        import active_scans, scan_cache, close_redis, _get_redis
    from arch.db           import AsyncDB
    from arch.http_client  import start_client, close_client
    from arch.browser_pool import browser_pool
    from arch.handlers     import cmd_vuln_v51, cmd_api_discover_v51, run_single_engine_v51
    from arch.reporting    import format_vuln_report, format_engine_result
except ModuleNotFoundError:
    # ဖိုင်တွေ root မှာ တင်ထားတဲ့ case
    from state        import active_scans, scan_cache, close_redis, _get_redis
    from db           import AsyncDB
    from http_client  import start_client, close_client
    from browser_pool import browser_pool
    from handlers     import cmd_vuln_v51, cmd_api_discover_v51, run_single_engine_v51
    from reporting    import format_vuln_report, format_engine_result

# ── Config ────────────────────────────────────────────────────────────────────
BOT_TOKEN   = os.getenv("BOT_TOKEN", "")
DATA_DIR    = os.getenv("DATA_DIR", "/app/data")
SQLITE_FILE = os.path.join(DATA_DIR, "bot_db.sqlite")
DB_FILE     = os.path.join(DATA_DIR, "bot_db.json")

os.makedirs(DATA_DIR, exist_ok=True)

# ── DB singleton ──────────────────────────────────────────────────────────────
db = AsyncDB(SQLITE_FILE)


# ── post_init ─────────────────────────────────────────────────────────────────
async def post_init(application) -> None:
    await db.init()
    await db.migrate_from_json(DB_FILE)
    logger.info("✅ AsyncDB ready")

    await start_client()
    logger.info("✅ aiohttp session pool ready")

    await browser_pool.start()
    logger.info("✅ Browser pool ready")

    async def _cleanup_loop():
        while True:
            await asyncio.sleep(300)
            await scan_cache.cleanup()

    asyncio.create_task(_cleanup_loop(), name="cache_cleanup")

    r = await _get_redis()
    if r:
        logger.info("✅ Redis connected")
    else:
        logger.info("⚠️  Redis မရှိ — local fallback သုံးမယ်")


# ── post_shutdown ─────────────────────────────────────────────────────────────
async def post_shutdown(application) -> None:
    await browser_pool.stop()
    await close_client()
    await close_redis()
    logger.info("✅ Shutdown complete")


# ── Engine handler factory ────────────────────────────────────────────────────
def make_engine_handler(engine_name, engine_fn, label, emoji):
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


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    from telegram.ext import (
        Application, CommandHandler, MessageHandler, filters,
    )

    if not BOT_TOKEN:
        raise SystemExit("❌ BOT_TOKEN မထည့်ရသေးဘူး — Railway Variables မှာ ထည့်ပါ")

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    # ── bot_v50_final.py ထဲက handler တွေ import ──────────────────────────────
    try:
        from bot_v50_final import (
            _sqli_engine_sync, _xss_engine_sync, _ssrf_engine_sync,
            _lfi_engine_sync, _auth_engine_sync,
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
        raise SystemExit(f"❌ bot_v50_final.py import မရဘူး: {exc}")

    # ── မပြောင်းထားတဲ့ handler တွေ ────────────────────────────────────────────
    app.add_handler(CommandHandler("start",              cmd_start))
    app.add_handler(CommandHandler("help",               cmd_help))
    app.add_handler(CommandHandler("status",             cmd_status))
    app.add_handler(CommandHandler("history",            cmd_history))
    app.add_handler(CommandHandler("mystats",            cmd_mystats))
    app.add_handler(CommandHandler("stop",               cmd_stop))
    app.add_handler(CommandHandler("resume",             cmd_resume))
    app.add_handler(CommandHandler("dl",                 cmd_dl))
    app.add_handler(CommandHandler("scan",               cmd_scan))
    app.add_handler(CommandHandler("recon",              cmd_recon))
    app.add_handler(CommandHandler("discover",           cmd_discover))
    app.add_handler(CommandHandler("monitor",            cmd_monitor))
    app.add_handler(CommandHandler("screenshot",         cmd_screenshot))
    app.add_handler(CommandHandler("appassets",          cmd_appassets))
    app.add_handler(CommandHandler("jwtattack",          cmd_jwtattack))
    app.add_handler(CommandHandler("admin",              cmd_admin))
    app.add_handler(CommandHandler("ban",                cmd_ban))
    app.add_handler(CommandHandler("unban",              cmd_unban))
    app.add_handler(CommandHandler("userinfo",           cmd_userinfo))
    app.add_handler(CommandHandler("broadcast",          cmd_broadcast))
    app.add_handler(CommandHandler("allusers",           cmd_allusers))
    app.add_handler(CommandHandler("setforcejoin",       cmd_setforcejoin))
    app.add_handler(CommandHandler("sys",                cmd_sys))
    app.add_handler(CommandHandler("adminset",           cmd_adminset))
    app.add_handler(CommandHandler("botstats",           cmd_botstats))
    app.add_handler(CommandHandler("tech_stack",         cmd_tech_stack))
    app.add_handler(CommandHandler("api_fuzzer",         cmd_api_fuzzer))
    app.add_handler(CommandHandler("password_leak_check",cmd_password_leak_check))
    app.add_handler(CommandHandler("site_map",           cmd_site_map))
    app.add_handler(CommandHandler("whois",              cmd_whois))
    app.add_handler(CommandHandler("whois_lookup",       cmd_whois_lookup))
    app.add_handler(CommandHandler("dns_enum",           cmd_dns_enum))
    app.add_handler(CommandHandler("port_scan",          cmd_port_scan))
    app.add_handler(CommandHandler("ssl_check",          cmd_ssl_check))
    app.add_handler(CommandHandler("headers_check",      cmd_headers_check))
    app.add_handler(CommandHandler("waf_detect",         cmd_waf_detect))
    app.add_handler(CommandHandler("cors_check",         cmd_cors_check))
    app.add_handler(CommandHandler("dir_brute",          cmd_dir_brute))
    app.add_handler(CommandHandler("subdomain_enum",     cmd_subdomain_enum))
    app.add_handler(CommandHandler("cms_detect",         cmd_cms_detect))
    app.add_handler(CommandHandler("speed_audit",        cmd_speed_audit))
    app.add_handler(CommandHandler("graphql",            cmd_graphql))
    app.add_handler(CommandHandler("js_restore",         cmd_js_restore))
    app.add_handler(CommandHandler("fixall",             cmd_fixall))
    app.add_handler(CommandHandler("cloudcheck",         cmd_cloudcheck))
    app.add_handler(CommandHandler("paramfuzz",          cmd_paramfuzz))
    app.add_handler(CommandHandler("autopwn",            cmd_autopwn))
    app.add_handler(CommandHandler("api",                cmd_api_unified))

    # ── v51 အသစ်ပြင်ထားတဲ့ handler တွေ ──────────────────────────────────────
    app.add_handler(CommandHandler("vuln",         cmd_vuln_v51))
    app.add_handler(CommandHandler("api_discover", cmd_api_discover_v51))

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

    app.add_handler(MessageHandler(filters.Document.ALL, handle_app_upload))

    logger.info("🚀 Bot v51 စတင်နေပြီ...")
    app.run_polling(
        allowed_updates=["message", "callback_query"],
        close_loop=False,
    )


if __name__ == "__main__":
    main()

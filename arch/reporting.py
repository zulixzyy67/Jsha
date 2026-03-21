"""
arch/reporting.py  —  Fixed Vulnerability Report Formatters
=============================================================

BUG FIXED (Issue #1 from the task)
────────────────────────────────────
The original `_run_single_engine()` always rendered the "Fix Guide" block
regardless of whether a vulnerability was found:

    # ORIGINAL — BUGGY:
    lines.append("✅ *No vulnerability found*")   # branch A

    fix = result.get("fix", [])                   # ← outside the if/else!
    if fix:                                        # ← runs even on branch A
        lines += ["", "*🔧 Fix Guide:*"]          #   ← BUG: shows HOW TO FIX
        for f in fix:                             #     when no vuln found
            lines.append(f"  • {f}")

Fix: move the `fix` block INSIDE the `if is_vuln:` branch.

Additionally, `_format_vuln_report()` always rendered the Clickjacking
"Fix" line even when the site was NOT vulnerable.  Fixed below with an
explicit `else: ✅ Protected` clause that omits the fix recommendation.

This module re-implements both formatters cleanly and exports the fixed
versions so the main bot file can import them as drop-in replacements.
"""

from __future__ import annotations

from collections import Counter
from urllib.parse import urlparse
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════════════
# Severity helpers (kept local — no import cycle)
# ═══════════════════════════════════════════════════════════════════════════════

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}
_REMEDIATION_HINTS = {
    "CRITICAL": "🔧 _Immediately restrict access & rotate credentials_",
    "HIGH":     "🔧 _Restrict access via server config or .htaccess_",
    "MEDIUM":   "🔧 _Review exposure and apply access controls_",
    "LOW":      "🔧 _Consider restricting public access_",
    "INFO":     "",
}


# ═══════════════════════════════════════════════════════════════════════════════
# 1.  Fixed _format_vuln_report
# ═══════════════════════════════════════════════════════════════════════════════

def format_vuln_report(r: dict) -> str:
    """
    Format the dict returned by _vuln_scan_sync() into a Telegram Markdown
    message.

    FIXES vs v50:
      • Clickjacking "HOW TO FIX" line only appears when vulnerable=True.
      • Missing-headers section only lists fix recommendations for headers
        that are actually missing (not a blanket block).
      • Executive summary only rendered when there are actual findings.
      • Error-rate warning only shown when error_rate > 0.15.
    """
    domain = urlparse(r.get("url", "")).netloc or r.get("url", "?")
    lines: list[str] = []

    # ── Flatten all exposed findings ──────────────────────────────────────────
    all_exposed: list = []
    for f in r.get("findings", []):
        for fi in f.get("exposed", []):
            fi["_netloc"] = f.get("netloc", domain)
            all_exposed.append(fi)

    # ── Overall risk classification ───────────────────────────────────────────
    all_sevs = {fi["severity"] for fi in all_exposed}
    if "CRITICAL" in all_sevs:
        overall = "🔴 CRITICAL RISK"
    elif "HIGH" in all_sevs:
        overall = "🟠 HIGH RISK"
    elif "MEDIUM" in all_sevs or r.get("clickjacking"):
        overall = "🟡 MEDIUM RISK"
    elif r.get("missing_headers"):
        overall = "🔵 LOW RISK"
    else:
        overall = "✅ CLEAN"

    cf_badge = " ☁️ Cloudflare" if r.get("cloudflare") else ""

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        "🛡️ *Vulnerability Scan Report*",
        f"🌐 `{domain}`{cf_badge}",
        f"📊 Risk: *{overall}*",
        f"🔍 Paths: `{r.get('total_scanned', 0)}` | Issues: `{len(all_exposed)}`",
        f"📡 Subdomains: `{len(r.get('subdomains_found', []))}`",
        f"🖥️ Server: `{r.get('server', 'Unknown')}`",
        "",
    ]

    # ── Executive summary — ONLY when there are findings ─────────────────────
    if all_exposed:
        sev_counts = Counter(fi["severity"] for fi in all_exposed)
        lines.append("*📊 Finding Summary:*")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = sev_counts.get(sev, 0)
            if count:
                lines.append(f"  {_SEV_EMOJI[sev]} `{sev}`: `{count}` finding(s)")
        lines.append("")

    # ── HTTPS ─────────────────────────────────────────────────────────────────
    lines.append("*🔐 HTTPS:*")
    if r.get("https"):
        lines.append("  ✅ HTTPS enabled")
    else:
        lines.append("  🔴 HTTP only — no encryption!")
        lines.append("  🔧 Fix: Redirect all HTTP → HTTPS, obtain a TLS certificate")
    lines.append("")

    # ── Subdomains ────────────────────────────────────────────────────────────
    if r.get("subdomains_found"):
        lines.append("*📡 Live Subdomains:*")
        for s in r["subdomains_found"]:
            lines.append(f"  • `{urlparse(s).netloc}`")
        lines.append("")

    # ── Findings grouped by severity — ONLY when present ─────────────────────
    if all_exposed:
        lines += ["*🚨 Findings by Severity:*", ""]
        for sev_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            level_findings = [fi for fi in all_exposed if fi["severity"] == sev_level]
            if not level_findings:
                continue
            em = _SEV_EMOJI[sev_level]
            lines.append(f"{em} *{sev_level}* ({len(level_findings)})")
            lines.append("─" * 20)
            for fi in level_findings:
                netloc_note = (
                    f" _(on `{fi['_netloc']}`)"
                    if fi.get("_netloc") and fi["_netloc"] != domain else ""
                )
                ct_note = (
                    f" `[{fi.get('content_type', '')}]`"
                    if fi.get("content_type") else ""
                )
                lines.append(f"  • {fi['label']}{netloc_note}")
                lines.append(f"    🔗 `{fi['full_url']}`")
                lines.append(f"    HTTP `{fi['status']}`{ct_note}")
            hint = _REMEDIATION_HINTS.get(sev_level, "")
            if hint:
                lines.append(f"  {hint}")
            lines.append("")
    else:
        # ✅ Clean — no exposed files: NO mitigation steps shown
        lines += ["*✅ No exposed files found*", ""]

    # ── Protected (403) findings ──────────────────────────────────────────────
    all_protected = []
    for f in r.get("findings", []):
        for fi in f.get("protected", []):
            fi["_netloc"] = f.get("netloc", domain)
            all_protected.append(fi)
    if all_protected:
        lines.append("*⚠️ Blocked Paths (403 / Redirected):*")
        lines.append("_These paths exist but are access-controlled_")
        for fi in all_protected[:8]:
            em = _SEV_EMOJI.get(fi.get("severity", "INFO"), "⚪")
            lines.append(f"  {em} {fi['label']}")
            lines.append(f"    🔗 `{fi['full_url']}`")
        if len(all_protected) > 8:
            lines.append(f"  _…and {len(all_protected) - 8} more_")
        lines.append("")

    # ── Clickjacking — FIX SHOWN ONLY WHEN VULNERABLE ────────────────────────
    lines.append("*🖼️ Clickjacking:*")
    if r.get("clickjacking"):
        lines.append("  🟠 Vulnerable — no X-Frame-Options / frame-ancestors CSP")
        # ✅ FIX: these lines only appear inside the `if clickjacking` branch
        lines.append("  🔧 Fix: Add `X-Frame-Options: SAMEORIGIN`")
        lines.append("  🔧 Or CSP: `Content-Security-Policy: frame-ancestors 'self'`")
    else:
        # ✅ Clean — no fix recommendations shown
        lines.append("  ✅ Protected")
    lines.append("")

    # ── Missing Security Headers — FIX ONLY FOR ACTUALLY MISSING HEADERS ──────
    if r.get("missing_headers"):
        lines.append("*📋 Security Header Issues:*")
        sorted_hdrs = sorted(
            r["missing_headers"][:12],
            key=lambda x: _SEV_ORDER.get(x[2], 9),
        )
        for name, hdr, sev in sorted_hdrs:
            em = _SEV_EMOJI.get(sev, "⚪")
            if "leak" in name.lower() or "disclosure" in name.lower():
                lines.append(f"  {em} {name}: `{hdr}`")
            else:
                lines.append(f"  {em} Missing *{name}*")
                lines.append(f"    `{hdr}`")
        lines.append("")
    # ✅ If no missing headers → this section is entirely absent (no "All good!" filler)

    # ── Cloudflare note ───────────────────────────────────────────────────────
    if r.get("cloudflare"):
        lines += [
            "☁️ *Cloudflare note:*",
            "  Some paths may be hidden behind CF WAF.",
            "  403 results may indicate the file exists but CF blocks access.",
            "",
        ]

    # ── Scan quality warning — ONLY when error rate is high ──────────────────
    error_rate = r.get("error_rate", 0.0)
    if error_rate > 0.15:
        lines += [
            f"⚠️ *Scan quality notice:* `{error_rate:.0%}` of probes errored.",
            "  Results may be incomplete. Try again or check network.",
            "",
        ]

    lines += [
        "━━━━━━━━━━━━━━━━━━",
        "⚠️ _Passive scan only — no exploitation_",
    ]
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 2.  Fixed _run_single_engine result formatter
# ═══════════════════════════════════════════════════════════════════════════════

def format_engine_result(
    result: dict,
    label: str,
    emoji: str,
    domain: str,
) -> str:
    """
    Format the dict returned by a single scan engine
    (sqli, xss, ssrf, lfi, auth) into a Telegram Markdown message.

    BUG FIXED:
      • `fix` / "HOW TO FIX" section ONLY rendered when is_vuln=True.
      • When clean, the message ends at "✅ No vulnerability found" — no
        misleading mitigation steps appended.

    is_vuln detection covers all engine return conventions:
      • `result["vulnerable"]` — sqli, xss, lfi, auth engines
      • `result["ssrf_found"]` — ssrf engine
      • `result["redirect_found"]` — ssrf/open-redirect engine
    """
    is_vuln = (
        result.get("vulnerable", False)
        or result.get("ssrf_found", False)
        or result.get("redirect_found", False)
    )

    lines = [f"{emoji} *{label} — `{domain}`*", ""]

    if is_vuln:
        # ── Vulnerable branch ─────────────────────────────────────────────────
        lines.append("🔴 *VULNERABLE*\n")

        _SKIP_KEYS = frozenset(["fix", "dom_sinks", "vulnerable", "ssrf_found",
                                 "redirect_found", "progress"])
        for k, v in result.items():
            if k in _SKIP_KEYS or v is None or v is False or v == []:
                continue
            if isinstance(v, bool):
                lines.append(f"  {k}: `{v}`")
            elif isinstance(v, str) and len(v) < 200:
                lines.append(f"  {k}: `{v}`")
            elif isinstance(v, list) and v:
                lines.append(f"  {k}: `{', '.join(str(i) for i in v[:3])}`")

        # ✅ FIX: fix guide ONLY appended here, inside is_vuln=True branch
        fix = result.get("fix", [])
        if fix:
            lines += ["", "*🔧 How to Fix:*"]
            for step in fix[:8]:
                lines.append(f"  • {step}")

    else:
        # ── Clean branch — NO mitigation steps ───────────────────────────────
        lines.append("✅ *No vulnerability found*")
        # ✅ FIX: nothing else added here — no "HOW TO FIX" after a clean result

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 3.  Fixed API discovery summary formatter
# ═══════════════════════════════════════════════════════════════════════════════

def format_api_discovery(result: dict, domain: str) -> str:
    """
    Format the dict returned by discover_api_endpoints().

    BUG FIXED:
      • CORS misconfig "fix" text ONLY shown when wildcard origin detected.
      • "No endpoints" branch cleanly exits with a single message — no
        partial mitigation blocks appended.
    """
    from urllib.parse import urlparse as _up

    endpoints  = result.get("found", [])
    js_mined   = result.get("js_mined", [])
    html_mined = result.get("html_mined", [])
    robots     = result.get("robots", [])
    stats      = result.get("stats", {})

    json_apis    = [e for e in endpoints if e["type"] in ("JSON_API", "GRAPHQL")]
    xml_feeds    = [e for e in endpoints if e["type"] == "XML/RSS"]
    api_docs     = [e for e in endpoints if e["type"] == "API_DOCS"]
    config_leaks = [e for e in endpoints if e["type"] == "CONFIG_LEAK"]
    source_maps  = [e for e in endpoints if e["type"] == "SOURCE_MAP"]
    protected    = [e for e in endpoints if e["type"] == "PROTECTED"]
    others       = [e for e in endpoints if e["type"] == "OTHER"]
    cors_vulns   = [e for e in endpoints if e.get("cors") and "*" in str(e.get("cors", ""))]
    all_mined    = list(set(js_mined + html_mined + robots))

    # ── No results branch ─────────────────────────────────────────────────────
    if not endpoints and not all_mined:
        return (
            f"🔌 *API Discovery — `{domain}`*\n\n"
            f"📭 No API endpoints found\n"
            f"_(protected or non-standard paths)_\n\n"
            f"🔍 Probed: `{stats.get('total_probed', 0)}` paths"
        )

    lines = [
        f"🔌 *API Discovery — `{domain}`*",
        "━━━━━━━━━━━━━━━━━━━━",
        f"📊 Endpoints: `{len(endpoints)}` | 🔍 Probed: `{stats.get('total_probed',0)}`",
        f"📦 JS mined: `{stats.get('js_urls_found',0)}` | 🌐 HTML mined: `{stats.get('html_urls_found',0)}`",
        "",
    ]

    # High-risk first
    high_risk = sorted(
        [e for e in endpoints if e.get("risk", 0) >= 30],
        key=lambda e: e.get("risk", 0), reverse=True,
    )
    if high_risk:
        lines.append(f"*🔴 High Risk Endpoints ({len(high_risk)}):*")
        for e in high_risk[:8]:
            path  = _up(e["url"]).path or e["url"]
            rsk   = e.get("risk", 0)
            ttype = e.get("type", "")
            wflag = " ⚠️WRITE" if "WRITE" in e.get("allow_methods", "") else ""
            cors  = " ✦CORS" if e.get("cors") else ""
            lines.append(f"  🔴 `{path}` [{ttype}] risk:`{rsk}`{wflag}{cors}")
        lines.append("")

    if json_apis:
        lines.append(f"*✅ JSON / GraphQL APIs ({len(json_apis)}):*")
        for e in json_apis[:20]:
            path  = _up(e["url"]).path or e["url"]
            tag   = " 〔GraphQL〕" if e["type"] == "GRAPHQL" else ""
            cors  = " ✦CORS" if e.get("cors") else ""
            meth  = f" [{e.get('method','GET')}]" if e.get("method","GET") != "GET" else ""
            lines.append(f"  🟢 `{path}`{tag}{cors}{meth}")
            prev  = e.get("preview","")[:60].replace("\n"," ")
            if prev:
                lines.append(f"     _{prev}_")
        lines.append("")

    if xml_feeds:
        lines.append(f"*📰 RSS / XML Feeds ({len(xml_feeds)}):*")
        for e in xml_feeds[:10]:
            lines.append(f"  📡 `{_up(e['url']).path or e['url']}`")
        lines.append("")

    if api_docs:
        lines.append(f"*📖 API Docs / Swagger ({len(api_docs)}):*")
        for e in api_docs[:5]:
            note = f" — {e['note']}" if e.get("note") else ""
            lines.append(f"  📘 `{_up(e['url']).path or e['url']}`{note}")
        lines.append("")

    if config_leaks:
        lines.append(f"*🚨 Config / File Leaks ({len(config_leaks)}):*")
        for e in config_leaks[:8]:
            path = _up(e["url"]).path or e["url"]
            prev = e.get("preview","")[:50].replace("\n"," ")
            lines.append(f"  ⚠️ `{path}` [{e.get('size_b','?')}B]")
            if prev:
                lines.append(f"     _{prev}_")
        lines.append("")

    if source_maps:
        lines.append(f"*🗺 Source Maps Exposed ({len(source_maps)}):*")
        for e in source_maps[:5]:
            lines.append(f"  🔓 `{_up(e['url']).path or e['url']}` [{e.get('size_b','?')}B]")
        lines.append("")

    if protected:
        lines.append(f"*🔒 Protected — Exists ({len(protected)}):*")
        for e in protected[:10]:
            path  = _up(e["url"]).path or e["url"]
            note  = f" [{e.get('note', e.get('status',''))}]"
            cors  = " ✦CORS" if e.get("cors") else ""
            lines.append(f"  🔐 `{path}`{note}{cors}")
        lines.append("")

    if all_mined:
        unique_mined = sorted({_up(u).path for u in all_mined if _up(u).path})[:20]
        lines.append(f"*🕵️ Mined from JS/HTML ({len(all_mined)} total):*")
        for p in unique_mined:
            lines.append(f"  🔎 `{p}`")
        lines.append("")

    if others:
        lines.append(f"*📄 Other ({len(others)}):*")
        for e in others[:5]:
            lines.append(f"  📋 `{_up(e['url']).path or e['url']}`")
        lines.append("")

    # ── CORS — fix ONLY shown when wildcard misconfig actually detected ────────
    if cors_vulns:
        lines.append(f"*🌍 CORS Misconfiguration ({len(cors_vulns)}):*")
        for e in cors_vulns[:5]:
            path = _up(e["url"]).path
            lines.append(f"  🌐 `{path}` → `{e['cors']}`")
        # ✅ FIX: this recommendation only appears because cors_vulns is non-empty
        lines.append("  🔧 Fix: Replace `Access-Control-Allow-Origin: *` with an explicit allowlist")
        lines.append("")
    elif any(e.get("cors") for e in endpoints):
        # CORS present but not wildcard — informational only, no fix needed
        cors_list = [e for e in endpoints if e.get("cors")]
        lines.append(f"*🌍 CORS Enabled ({len(cors_list)}):*")
        for e in cors_list[:5]:
            path = _up(e["url"]).path
            lines.append(f"  🌐 `{path}` → `{e['cors']}`")
        lines.append("")

    lines.append("⚠️ _Passive scan only — no exploitation_")
    return "\n".join(lines)

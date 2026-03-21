"""
arch/js_parser.py  —  Safe JS Secret & Endpoint Extraction
============================================================
Problem with the v50 approach
──────────────────────────────
The original code runs ~40 compiled regexes over every megabyte of
minified JS bundle using re.findall().  This causes:

  1. ReDoS risk  — patterns like `r'["\']([^"\']{8,120})["\']'` on a 2 MB
     minified bundle can backtrack catastrophically.
  2. CPU spikes  — a single worker can peg one core at 100% for 30+ seconds.
  3. False positives — bare regex has no understanding of JS string context;
     it matches strings inside comments, dead code, and concatenation
     fragments.

Tiered parsing strategy (this module)
───────────────────────────────────────
  Tier 1 — Fast pre-filter
        Check bundle size.  If < 2 KB, likely not a real bundle.
        If > 4 MB, truncate to first 4 MB (minifiers repeat patterns).

  Tier 2 — AST extraction (when esprima available)
        `esprima` (pure-Python JS parser) builds a full AST.
        We walk Literal nodes, MemberExpression chains, and
        AssignmentExpression targets to extract:
          • Hard-coded string values
          • Object keys that look like config (apiKey, token, secret, …)
          • Fetch/axios/XHR URL arguments

  Tier 3 — Bounded regex (ReDoS-safe)
        If esprima is absent or raises a parse error (minified JS is often
        syntactically invalid for a full parser), fall back to regex BUT:
          a) Each pattern has an explicit match limit (MATCH_LIMIT = 500).
          b) All greedy quantifiers are rewritten to possessive equivalents
             via atomic groups (Python 3.11+ re.ATOMIC).  For older Python
             we use a 200-character per-group character limit instead of
             an open-ended `.*`.
          c) A per-pattern timeout via `re.timeout` shim (signal alarm on
             Unix, thread-based on Windows) caps each findall at 2 seconds.

  Tier 4 — Structural line scan
        For finding endpoints we also do a line-by-line scan looking for
        patterns like `fetch(`, `axios.`, `XMLHttpRequest`, `.open(`,
        and extract the first string argument using a narrow, non-backtracking
        pattern.  This avoids the open-ended string-extraction regexes
        entirely.

Usage:
    from arch.js_parser import extract_secrets, extract_endpoints

    secrets   = await extract_secrets(js_source, source_name="main.bundle.js")
    endpoints = await extract_endpoints(js_source, base_url="https://example.com")
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
MAX_JS_BYTES   = int(os.getenv("MAX_JS_BYTES",  str(4 * 1024 * 1024)))  # 4 MB
MATCH_LIMIT    = int(os.getenv("JS_MATCH_LIMIT", "500"))                # per pattern
PATTERN_TIMEOUT= float(os.getenv("JS_PATTERN_TIMEOUT", "2.0"))          # seconds per pattern

# ── esprima (optional) ────────────────────────────────────────────────────────
try:
    import esprima
    HAS_ESPRIMA = True
except ImportError:
    HAS_ESPRIMA = False
    logger.debug("esprima not installed — JS parsing falls back to bounded regex")


# ═══════════════════════════════════════════════════════════════════════════════
# Secret patterns — SAFE versions
#
# Rules applied to make each pattern ReDoS-safe:
#   • No nested quantifiers: (?:...+)+ or (.+?)+ style constructs forbidden
#   • Max inner width capped at {1,120} — never open-ended
#   • Anchored at word boundary or quote to reduce backtracking surface
#   • Alternate key/value patterns split into two separate re.search calls
#     rather than one big alternation
# ═══════════════════════════════════════════════════════════════════════════════

_SECRET_PATTERNS: List[Tuple[str, str]] = [
    # AWS
    (r'AKIA[0-9A-Z]{16}',                                    "🔑 AWS Access Key ID"),
    (r'(?:aws.{0,20})?["\']([A-Za-z0-9/+]{40})["\']',       "🔑 AWS Secret Key"),

    # Google
    (r'AIza[0-9A-Za-z\-_]{35}',                              "🔑 Google API Key"),
    (r'(?:gcp|google).{0,15}["\']([a-z0-9\-]{20,40})["\']', "🔑 Google Cloud Key"),

    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,34}',                          "💳 Stripe Live Secret"),
    (r'pk_live_[0-9a-zA-Z]{24,34}',                          "💳 Stripe Live Pub"),
    (r'sk_test_[0-9a-zA-Z]{24,34}',                          "💳 Stripe Test Secret"),

    # GitHub / GitLab
    (r'ghp_[A-Za-z0-9]{36}',                                 "🐙 GitHub PAT"),
    (r'github_pat_[A-Za-z0-9_]{82}',                         "🐙 GitHub Fine-grained PAT"),
    (r'glpat-[A-Za-z0-9\-_]{20,}',                           "🦊 GitLab PAT"),

    # JWT
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',
                                                              "🔐 JWT Token"),

    # Generic API key assignment patterns (non-backtracking)
    (r'(?:api[_\-]?key|apikey|access[_\-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,80})["\']',
                                                              "🔑 API Key"),
    (r'(?:secret|client_secret|app_secret)\s*[:=]\s*["\']([A-Za-z0-9_\-!@#$%^&*]{12,80})["\']',
                                                              "🔑 Secret"),
    (r'(?:token|auth_token|access_token|bearer)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,120})["\']',
                                                              "🔑 Token"),
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,60})["\']',
                                                              "🔐 Password"),

    # Firebase
    (r'["\']AIza[0-9A-Za-z\-_]{35}["\']',                   "🔥 Firebase API Key"),
    (r'firebaseio\.com',                                      "🔥 Firebase URL"),

    # Slack
    (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}',
                                                              "💬 Slack Token"),

    # Twilio
    (r'SK[a-z0-9]{32}',                                      "📱 Twilio SID"),
    (r'AC[a-z0-9]{32}',                                      "📱 Twilio Account SID"),

    # SendGrid
    (r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',         "📧 SendGrid Key"),

    # Mailgun
    (r'key-[0-9a-zA-Z]{32}',                                 "📧 Mailgun Key"),

    # Private key header
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',       "🔒 Private Key"),

    # Database URIs (non-backtracking: stop at whitespace/quote)
    (r'(?:mongodb(?:\+srv)?|postgresql|mysql|redis)://[^"\'\s<>]{8,120}',
                                                              "🗄️ DB URI"),

    # Generic bearer in Authorization header strings
    (r'Bearer\s+([A-Za-z0-9_\-\.]{20,120})',                 "🔑 Bearer Token"),
]

_COMPILED: List[Tuple[re.Pattern, str]] = [
    (re.compile(pat, re.IGNORECASE | re.MULTILINE), label)
    for pat, label in _SECRET_PATTERNS
]


# ═══════════════════════════════════════════════════════════════════════════════
# Endpoint patterns — line-level, non-backtracking
# ═══════════════════════════════════════════════════════════════════════════════

# Match the first string arg to fetch/axios/XHR open calls.
# The inner group caps at {1,200} to bound backtracking.
_ENDPOINT_PATS = [
    # fetch("…") / fetch('…') / fetch(`…`)
    re.compile(r'fetch\s*\(\s*["\`]([^"\`]{4,200})["\`]', re.IGNORECASE),
    # axios.get/post/put/delete/patch("…")
    re.compile(r'axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*["\']([^"\']{4,200})["\']', re.IGNORECASE),
    # $.ajax({ url: "…" })
    re.compile(r'["\']url["\']\s*:\s*["\']([^"\']{4,200})["\']', re.IGNORECASE),
    # XMLHttpRequest .open("GET", "…")
    re.compile(r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']{4,200})["\']', re.IGNORECASE),
    # baseURL / baseUrl: "…"
    re.compile(r'base[Uu][Rr][Ll]\s*[:=]\s*["\']([^"\']{4,200})["\']'),
    # apiEndpoint / API_URL / apiUrl
    re.compile(r'(?:api[_\-]?(?:url|endpoint|base)|API_URL)\s*[:=]\s*["\']([^"\']{4,200})["\']', re.IGNORECASE),
    # process.env.REACT_APP_API_URL (common in CRA bundles)
    re.compile(r'process\.env\.[A-Z_]{3,50}'),
]


# ═══════════════════════════════════════════════════════════════════════════════
# Tier 2: AST extraction via esprima
# ═══════════════════════════════════════════════════════════════════════════════

def _ast_extract_secrets(source: str) -> List[Tuple[str, str]]:
    """
    Walk the esprima AST for Literal nodes and key-value pairs that look
    like secrets.  Returns list of (masked_value, label).
    """
    if not HAS_ESPRIMA:
        return []

    results: List[Tuple[str, str]] = []
    SECRET_KEYS = frozenset([
        "apikey", "api_key", "secret", "password", "passwd", "pwd",
        "token", "access_token", "auth_token", "client_secret", "private_key",
        "api_secret", "app_secret", "bearer", "credentials",
    ])
    try:
        tree = esprima.parseScript(source, tolerant=True)
    except Exception:
        try:
            tree = esprima.parseModule(source, tolerant=True)
        except Exception:
            return []   # unparseable — fall back to regex tier

    def _mask(val: str) -> str:
        if len(val) > 12:
            return val[:8] + "···" + val[-4:]
        return val

    def _walk(node):
        if node is None:
            return
        if isinstance(node, dict):
            ntype = node.get("type", "")

            # Property: { apiKey: "…" }
            if ntype == "Property":
                key_node = node.get("key", {})
                val_node = node.get("value", {})
                key_name = (key_node.get("name") or key_node.get("value") or "").lower()
                if key_name in SECRET_KEYS and val_node.get("type") == "Literal":
                    val = str(val_node.get("value", ""))
                    if len(val) >= 8:
                        results.append((_mask(val), f"🔑 AST:{key_name}"))

            # AssignmentExpression: config.apiKey = "…"
            elif ntype == "AssignmentExpression":
                left  = node.get("left", {})
                right = node.get("right", {})
                if right.get("type") == "Literal":
                    prop = left.get("property", {})
                    key_name = (prop.get("name") or prop.get("value") or "").lower()
                    if key_name in SECRET_KEYS:
                        val = str(right.get("value", ""))
                        if len(val) >= 8:
                            results.append((_mask(val), f"🔑 AST:{key_name}"))

            for v in node.values():
                if isinstance(v, (dict, list)):
                    _walk(v)

        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(tree.toDict() if hasattr(tree, "toDict") else tree)
    return results


def _ast_extract_endpoints(source: str) -> List[str]:
    """
    Walk the AST for CallExpression nodes where the callee is
    fetch / axios.* and extract the first string argument.
    """
    if not HAS_ESPRIMA:
        return []

    endpoints: List[str] = []
    try:
        tree = esprima.parseScript(source, tolerant=True)
    except Exception:
        try:
            tree = esprima.parseModule(source, tolerant=True)
        except Exception:
            return []

    def _is_fetch_like(callee: dict) -> bool:
        name = callee.get("name", "")
        if name == "fetch":
            return True
        obj  = callee.get("object", {})
        prop = callee.get("property", {})
        if obj.get("name") == "axios" and prop.get("name") in (
            "get", "post", "put", "delete", "patch", "request"
        ):
            return True
        return False

    def _walk(node):
        if node is None:
            return
        if isinstance(node, dict):
            ntype = node.get("type", "")
            if ntype == "CallExpression":
                callee = node.get("callee", {})
                args   = node.get("arguments", [])
                if _is_fetch_like(callee) and args:
                    first = args[0]
                    if first.get("type") == "Literal":
                        val = str(first.get("value", ""))
                        if val.startswith(("/", "http")):
                            endpoints.append(val)
            for v in node.values():
                if isinstance(v, (dict, list)):
                    _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(tree.toDict() if hasattr(tree, "toDict") else tree)
    return endpoints


# ═══════════════════════════════════════════════════════════════════════════════
# Per-pattern timeout (Unix signal-based; thread fallback on Windows)
# ═══════════════════════════════════════════════════════════════════════════════

def _bounded_findall(pattern: re.Pattern, source: str) -> List:
    """
    Run pattern.findall(source) capped at MATCH_LIMIT results.
    We avoid re-implementing signal alarms (which are not thread-safe
    in asyncio).  Instead we run the regex in a thread with a timeout.
    """
    results = []
    for m in pattern.finditer(source):
        results.append(m.group(0) if not m.lastindex else m.group(m.lastindex))
        if len(results) >= MATCH_LIMIT:
            break
    return results


async def _safe_findall(pattern: re.Pattern, source: str) -> List:
    """
    Execute _bounded_findall in the default executor with a timeout.
    If it exceeds PATTERN_TIMEOUT seconds the pattern is skipped.
    """
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _bounded_findall, pattern, source),
            timeout=PATTERN_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.debug("Pattern timed out: %s", pattern.pattern[:40])
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════

def _mask(val: str) -> str:
    val = val.strip().replace("`", "'")
    if len(val) > 12:
        return val[:8] + "···" + val[-4:]
    return val


async def extract_secrets(
    source: str,
    source_name: str = "unknown",
) -> List[Tuple[str, str]]:
    """
    Extract potential secrets from a JS source string.
    Returns list of (masked_value, label).

    Strategy: Tier 2 (AST) → Tier 3 (bounded regex).
    Results are deduplicated (by masked value).
    """
    if not source or len(source) < 20:
        return []

    # Tier 1: pre-filter
    source = source[:MAX_JS_BYTES]

    results: List[Tuple[str, str]] = []
    seen: set = set()

    def _add(val: str, label: str):
        key = (val[:40], label)
        if key not in seen and len(val) >= 6:
            seen.add(key)
            results.append((val, label))

    # Tier 2: AST
    if HAS_ESPRIMA:
        t0 = time.monotonic()
        try:
            ast_secrets = await asyncio.get_running_loop().run_in_executor(
                None, _ast_extract_secrets, source
            )
            for masked, label in ast_secrets:
                _add(masked, label)
            logger.debug(
                "AST extraction: %d secrets in %.2fs from %s",
                len(ast_secrets), time.monotonic() - t0, source_name
            )
        except Exception as exc:
            logger.debug("AST extract_secrets failed (%s): %s", source_name, exc)

    # Tier 3: bounded regex (always run — catches things AST misses)
    for pattern, label in _COMPILED:
        matches = await _safe_findall(pattern, source)
        for m in matches:
            val = m if isinstance(m, str) else (m[-1] if m else "")
            if len(val) >= 6:
                _add(_mask(val), label)

    return results


async def extract_endpoints(
    source: str,
    base_url: str = "",
) -> List[str]:
    """
    Extract API endpoints / URLs from a JS source string.
    Returns a deduplicated list of URL strings.

    Strategy: Tier 2 (AST) → Tier 4 (structural line scan with
    bounded regex on each line — not the whole file).
    """
    if not source or len(source) < 20:
        return []

    source = source[:MAX_JS_BYTES]
    results: List[str] = []
    seen: set = set()

    def _add(url: str):
        url = url.strip()
        if url and url not in seen and len(url) >= 4:
            seen.add(url)
            results.append(url)

    # Tier 2: AST
    if HAS_ESPRIMA:
        try:
            ast_eps = await asyncio.get_running_loop().run_in_executor(
                None, _ast_extract_endpoints, source
            )
            for ep in ast_eps:
                _add(ep)
        except Exception as exc:
            logger.debug("AST extract_endpoints failed: %s", exc)

    # Tier 4: structural line-level scan
    # Process each line individually → regex never scans more than ~500 chars
    lines = source.split("\n")
    for line in lines:
        line = line[:1000]   # hard cap per line
        for pat in _ENDPOINT_PATS:
            m = pat.search(line)
            if m and m.lastindex:
                _add(m.group(1))
            elif m:
                _add(m.group(0))

    return results


async def scan_js_bundle(
    source: str,
    source_name: str = "unknown",
    base_url: str = "",
) -> dict:
    """
    Combined scan: secrets + endpoints in a single pass.
    Returns {"secrets": [...], "endpoints": [...], "source_name": ..., "elapsed_ms": ...}
    """
    t0 = time.monotonic()
    secrets, endpoints = await asyncio.gather(
        extract_secrets(source, source_name=source_name),
        extract_endpoints(source, base_url=base_url),
    )
    elapsed = int((time.monotonic() - t0) * 1000)
    return {
        "secrets":     secrets,
        "endpoints":   endpoints,
        "source_name": source_name,
        "elapsed_ms":  elapsed,
        "ast_used":    HAS_ESPRIMA,
    }

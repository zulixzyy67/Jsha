"""
tests/test_v51.py  —  Automated test suite for the v51 refactor
================================================================
Run with:  python -m pytest tests/test_v51.py -v
"""

import asyncio
import json
import sys
import os
import pytest

# ── Make arch importable ──────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ═══════════════════════════════════════════════════════════════════════════════
# 1.  Reporting — HOW-TO-FIX bug
# ═══════════════════════════════════════════════════════════════════════════════

from arch.reporting import format_engine_result, format_vuln_report, format_api_discovery


class TestReportingBugFix:
    """
    Validates the core UI logic bug:
      When no vulnerability is found, the output must NOT contain any
      "Fix" / "HOW TO FIX" / "🔧" content.
    """

    # ── format_engine_result ──────────────────────────────────────────────────

    def _clean_result(self):
        return {"vulnerable": False, "fix": ["Use prepared statements", "Sanitize inputs"]}

    def _vuln_result(self):
        return {
            "vulnerable": True,
            "param": "id",
            "db_type": "MySQL",
            "fix": ["Use prepared statements", "Sanitize inputs", "Least privilege DB user"],
        }

    def test_clean_result_has_no_fix_section(self):
        """✅ Clean → zero 'Fix' content in output."""
        out = format_engine_result(self._clean_result(), "SQLi Test", "💉", "example.com")
        assert "🔧" not in out, "Fix emoji should NOT appear for clean results"
        assert "Fix" not in out, "'Fix' text should NOT appear for clean results"
        assert "prepared statements" not in out, "Fix steps must not appear for clean results"
        assert "✅ *No vulnerability found*" in out

    def test_vuln_result_has_fix_section(self):
        """✅ Vulnerable → fix section IS shown."""
        out = format_engine_result(self._vuln_result(), "SQLi Test", "💉", "example.com")
        assert "🔴 *VULNERABLE*" in out
        assert "🔧" in out, "Fix emoji must appear for vulnerable results"
        assert "How to Fix" in out
        assert "prepared statements" in out

    def test_clean_ssrf_no_fix(self):
        """ssrf_found=False → no fix."""
        result = {"ssrf_found": False, "redirect_found": False,
                  "fix": ["Block internal IPs", "Allowlist outbound"]}
        out = format_engine_result(result, "SSRF Test", "🔁", "example.com")
        assert "🔧" not in out
        assert "Block internal IPs" not in out

    def test_vuln_ssrf_has_fix(self):
        """ssrf_found=True → fix present."""
        result = {"ssrf_found": True, "ssrf_param": "url",
                  "fix": ["Block internal IPs", "Allowlist outbound"]}
        out = format_engine_result(result, "SSRF Test", "🔁", "example.com")
        assert "🔴 *VULNERABLE*" in out
        assert "Block internal IPs" in out

    def test_redirect_found_has_fix(self):
        """redirect_found=True is treated as vulnerable."""
        result = {"redirect_found": True, "redirect_param": "next",
                  "fix": ["Use allowlist for redirect destinations"]}
        out = format_engine_result(result, "Open Redirect", "🔁", "example.com")
        assert "🔴 *VULNERABLE*" in out
        assert "allowlist" in out

    def test_empty_fix_list_no_section(self):
        """Vulnerable but fix=[] → no fix section header."""
        result = {"vulnerable": True, "param": "q", "fix": []}
        out = format_engine_result(result, "XSS", "🕷️", "example.com")
        assert "🔴 *VULNERABLE*" in out
        assert "How to Fix" not in out

    # ── format_vuln_report ────────────────────────────────────────────────────

    def _make_vuln_report(self, *, clickjacking=False, missing_headers=None,
                          findings=None):
        return {
            "url": "https://example.com",
            "findings": findings or [],
            "total_scanned": 50,
            "https": True,
            "clickjacking": clickjacking,
            "missing_headers": missing_headers or [],
            "cloudflare": False,
            "server": "nginx",
            "subdomains_found": [],
            "error_rate": 0.0,
        }

    def test_clean_vuln_report_no_clickjack_fix(self):
        """Clickjacking=False → no X-Frame-Options fix line."""
        r = self._make_vuln_report(clickjacking=False)
        out = format_vuln_report(r)
        assert "✅ Protected" in out
        assert "X-Frame-Options" not in out, \
            "X-Frame-Options fix must NOT appear when clickjacking=False"

    def test_vuln_clickjack_has_fix(self):
        """Clickjacking=True → fix recommendation shown."""
        r = self._make_vuln_report(clickjacking=True)
        out = format_vuln_report(r)
        assert "🟠 Vulnerable" in out
        assert "X-Frame-Options" in out

    def test_no_findings_no_executive_summary(self):
        """No findings → executive summary block absent."""
        r = self._make_vuln_report()
        out = format_vuln_report(r)
        assert "Finding Summary" not in out

    def test_with_findings_has_executive_summary(self):
        """Findings present → executive summary shown."""
        findings = [{
            "netloc": "example.com",
            "exposed": [{
                "label": ".git/config",
                "full_url": "https://example.com/.git/config",
                "status": 200,
                "severity": "HIGH",
                "content_type": "text/plain",
            }],
            "protected": [],
        }]
        r = self._make_vuln_report(findings=findings)
        out = format_vuln_report(r)
        assert "Finding Summary" in out
        assert "HIGH" in out

    def test_clean_report_no_http_fix_when_https(self):
        """HTTPS site → no TLS fix line."""
        r = self._make_vuln_report()
        out = format_vuln_report(r)
        assert "✅ HTTPS enabled" in out
        assert "Redirect all HTTP" not in out

    def test_http_only_site_has_tls_fix(self):
        """HTTP-only site → TLS fix recommendation shown."""
        r = self._make_vuln_report()
        r["https"] = False
        out = format_vuln_report(r)
        assert "HTTP only" in out
        assert "Redirect all HTTP" in out

    # ── format_api_discovery ──────────────────────────────────────────────────

    def test_no_endpoints_no_cors_fix(self):
        """No endpoints → no CORS fix text."""
        result = {"found": [], "js_mined": [], "html_mined": [], "robots": [],
                  "stats": {"total_probed": 100, "js_urls_found": 0, "html_urls_found": 0}}
        out = format_api_discovery(result, "example.com")
        assert "No API endpoints found" in out
        assert "CORS" not in out

    def test_wildcard_cors_shows_fix(self):
        """Wildcard CORS detected → fix recommendation shown."""
        result = {
            "found": [{
                "url": "https://example.com/api/v1/users",
                "type": "JSON_API", "status": 200, "method": "GET",
                "risk": 5, "cors": "*", "size_b": 200, "preview": "",
            }],
            "js_mined": [], "html_mined": [], "robots": [],
            "stats": {"total_probed": 50, "js_urls_found": 0, "html_urls_found": 0},
        }
        out = format_api_discovery(result, "example.com")
        assert "Replace" in out or "allowlist" in out.lower(), \
            "CORS fix must appear when wildcard origin detected"

    def test_non_wildcard_cors_no_fix(self):
        """Non-wildcard CORS → informational only, no fix text."""
        result = {
            "found": [{
                "url": "https://example.com/api/v1/users",
                "type": "JSON_API", "status": 200, "method": "GET",
                "risk": 5, "cors": "https://trusted.example.com",
                "size_b": 200, "preview": "",
            }],
            "js_mined": [], "html_mined": [], "robots": [],
            "stats": {"total_probed": 50, "js_urls_found": 0, "html_urls_found": 0},
        }
        out = format_api_discovery(result, "example.com")
        # Should show the CORS info but NOT the fix recommendation
        assert "Replace" not in out
        assert "allowlist" not in out.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 2.  RedisCache (local fallback — no Redis needed)
# ═══════════════════════════════════════════════════════════════════════════════

from arch.state import RedisCache, RedisDailyQuota, RedisActiveScans


class TestRedisCacheLocalFallback:

    def _cache(self):
        return RedisCache(ttl=1, max_local=5, ns="test_cache:")

    def test_set_and_get(self):
        c = self._cache()
        asyncio.get_event_loop().run_until_complete(c.set("k1", {"x": 1}))
        result = asyncio.get_event_loop().run_until_complete(c.get("k1"))
        assert result == {"x": 1}

    def test_miss_returns_none(self):
        c = self._cache()
        result = asyncio.get_event_loop().run_until_complete(c.get("nonexistent"))
        assert result is None

    def test_delete(self):
        c = self._cache()
        asyncio.get_event_loop().run_until_complete(c.set("k2", "val"))
        asyncio.get_event_loop().run_until_complete(c.delete("k2"))
        result = asyncio.get_event_loop().run_until_complete(c.get("k2"))
        assert result is None

    def test_ttl_expiry(self):
        import time
        c = self._cache()   # ttl=1 second
        asyncio.get_event_loop().run_until_complete(c.set("k3", "soon_expired"))
        time.sleep(1.05)
        result = asyncio.get_event_loop().run_until_complete(c.get("k3"))
        assert result is None

    def test_max_entries_eviction(self):
        c = self._cache()   # max_local=5
        loop = asyncio.get_event_loop()
        for i in range(10):
            loop.run_until_complete(c.set(f"key_{i}", i))
        # After 10 inserts with max=5, the cache should not exceed 5 entries
        assert len(c._local) <= 5


# ═══════════════════════════════════════════════════════════════════════════════
# 3.  RedisDailyQuota (local fallback)
# ═══════════════════════════════════════════════════════════════════════════════

class TestRedisDailyQuotaLocalFallback:

    def _quota(self):
        return RedisDailyQuota(ns="test_quota:")

    def test_initial_count_zero(self):
        q = self._quota()
        count = asyncio.get_event_loop().run_until_complete(q.count(999, "scan"))
        assert count == 0

    def test_increment(self):
        q = self._quota()
        loop = asyncio.get_event_loop()
        n1 = loop.run_until_complete(q.increment(888, "scan"))
        n2 = loop.run_until_complete(q.increment(888, "scan"))
        assert n1 == 1
        assert n2 == 2

    def test_check_within_limit(self):
        q = self._quota()
        loop = asyncio.get_event_loop()
        ok, remaining, msg = loop.run_until_complete(q.check(777, "scan", limit=5))
        assert ok is True
        assert remaining == 5
        assert msg == ""

    def test_check_at_limit(self):
        q = self._quota()
        loop = asyncio.get_event_loop()
        for _ in range(5):
            loop.run_until_complete(q.increment(666, "scan"))
        ok, remaining, msg = loop.run_until_complete(q.check(666, "scan", limit=5))
        assert ok is False
        assert remaining == 0
        assert "limit reached" in msg


# ═══════════════════════════════════════════════════════════════════════════════
# 4.  RedisActiveScans (local fallback)
# ═══════════════════════════════════════════════════════════════════════════════

class TestRedisActiveScansLocalFallback:

    def _scans(self):
        return RedisActiveScans(ns="test_scans")

    def test_set_and_contains(self):
        s = self._scans()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(s.set(12345, "Vuln scan"))
        assert loop.run_until_complete(s.contains(12345)) is True

    def test_get(self):
        s = self._scans()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(s.set(11111, "API scan"))
        assert loop.run_until_complete(s.get(11111)) == "API scan"

    def test_pop(self):
        s = self._scans()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(s.set(22222, "JS Restore"))
        loop.run_until_complete(s.pop(22222))
        assert loop.run_until_complete(s.contains(22222)) is False

    def test_sync_contains_uses_local_cache(self):
        """__contains__ for backward-compatible `if uid in active_scans` checks."""
        s = self._scans()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(s.set(33333, "Test"))
        assert 33333 in s      # sync path
        loop.run_until_complete(s.pop(33333))
        assert 33333 not in s  # sync path after pop


# ═══════════════════════════════════════════════════════════════════════════════
# 5.  AsyncDB (uses a temp SQLite file)
# ═══════════════════════════════════════════════════════════════════════════════

import tempfile
from arch.db import AsyncDB


class TestAsyncDB:

    def _db(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        tmp.close()
        return AsyncDB(tmp.name)

    def test_init_and_get_user_none(self):
        db = self._db()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(db.init())
        user = loop.run_until_complete(db.get_user(999999))
        assert user is None

    def test_upsert_and_get_user(self):
        db = self._db()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(db.init())
        user = {
            "name": "Alice", "banned": False, "daily_limit": None,
            "count_today": 3, "last_date": "2025-01-01",
            "total_downloads": 5, "total_scans": 10, "scans_today": 2,
            "downloads": [], "scan_history": [],
        }
        loop.run_until_complete(db.upsert_user(111, user))
        fetched = loop.run_until_complete(db.get_user(111))
        assert fetched is not None
        assert fetched["name"] == "Alice"
        assert fetched["total_scans"] == 10

    def test_is_banned_false(self):
        db = self._db()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(db.init())
        assert loop.run_until_complete(db.is_banned(999999)) is False

    def test_is_banned_true(self):
        db = self._db()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(db.init())
        user = {"name": "Spammer", "banned": True, "daily_limit": None,
                "count_today": 0, "last_date": "", "total_downloads": 0,
                "total_scans": 0, "scans_today": 0, "downloads": [], "scan_history": []}
        loop.run_until_complete(db.upsert_user(222, user))
        assert loop.run_until_complete(db.is_banned(222)) is True

    def test_get_set_setting(self):
        db = self._db()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(db.init())
        loop.run_until_complete(db.set_setting("global_daily_limit", 20))
        val = loop.run_until_complete(db.get_setting("global_daily_limit"))
        assert val == 20

    def test_increment_field(self):
        db = self._db()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(db.init())
        user = {"name": "Bob", "banned": False, "daily_limit": None,
                "count_today": 0, "last_date": "", "total_downloads": 0,
                "total_scans": 5, "scans_today": 0, "downloads": [], "scan_history": []}
        loop.run_until_complete(db.upsert_user(333, user))
        new_val = loop.run_until_complete(db.increment_field(333, "total_scans"))
        assert new_val == 6

    def test_append_scan_history(self):
        db = self._db()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(db.init())
        loop.run_until_complete(db.get_or_create_user(444, "TestUser"))
        loop.run_until_complete(db.append_scan_history(444, {"url": "https://example.com", "type": "vuln"}))
        user = loop.run_until_complete(db.get_user(444))
        assert len(user["scan_history"]) == 1
        assert user["scan_history"][0]["url"] == "https://example.com"


# ═══════════════════════════════════════════════════════════════════════════════
# 6.  JS Parser — safe regex / AST extraction
# ═══════════════════════════════════════════════════════════════════════════════

from arch.js_parser import extract_secrets, extract_endpoints, scan_js_bundle


class TestJSParser:

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_extract_aws_key(self):
        source = 'const key = "AKIAIOSFODNN7EXAMPLE"; // AWS'
        secrets = self._run(extract_secrets(source, "test.js"))
        labels = [label for _, label in secrets]
        assert any("AWS" in l for l in labels), f"Expected AWS key detection, got: {labels}"

    def test_extract_jwt(self):
        source = 'const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123def456ghi789";'
        secrets = self._run(extract_secrets(source))
        labels = [l for _, l in secrets]
        assert any("JWT" in l for l in labels), f"Expected JWT detection, got: {labels}"

    def test_extract_endpoint_fetch(self):
        source = 'fetch("/api/v1/users").then(r => r.json())'
        endpoints = self._run(extract_endpoints(source))
        assert "/api/v1/users" in endpoints

    def test_extract_endpoint_axios(self):
        source = 'axios.get("/api/v2/products", { headers: auth })'
        endpoints = self._run(extract_endpoints(source))
        assert "/api/v2/products" in endpoints

    def test_no_false_positive_short_strings(self):
        source = 'const x = "ok"; const y = "yes";'
        secrets = self._run(extract_secrets(source))
        # Short strings like "ok" / "yes" should not be flagged
        assert all(len(v) >= 6 for v, _ in secrets)

    def test_empty_source(self):
        secrets = self._run(extract_secrets(""))
        endpoints = self._run(extract_endpoints(""))
        assert secrets == []
        assert endpoints == []

    def test_large_source_truncated(self):
        """Parser must handle very large sources without hanging."""
        import time
        large = ("x" * 1000 + "\n") * 5000   # ~5 MB
        t0 = time.monotonic()
        result = self._run(scan_js_bundle(large, "big.js"))
        elapsed = time.monotonic() - t0
        assert elapsed < 10, f"Parser took too long on large input: {elapsed:.1f}s"

    def test_scan_js_bundle_returns_dict(self):
        source = 'const API_URL = "https://api.example.com/v1"; fetch(API_URL)'
        result = self._run(scan_js_bundle(source, "bundle.js", "https://example.com"))
        assert "secrets"   in result
        assert "endpoints" in result
        assert "elapsed_ms" in result
        assert isinstance(result["secrets"], list)
        assert isinstance(result["endpoints"], list)


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import subprocess, sys
    sys.exit(subprocess.call(["python", "-m", "pytest", __file__, "-v"]))

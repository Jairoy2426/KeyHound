"""
KeyHound — Detector test suite.

Covers:
  - Regex detection finds all 5 embedded fake keys in sample.js
  - Entropy engine flags the high-entropy unknown token
  - Deduplication removes the duplicate GitHub token
  - Verifier is NOT called during tests (all external calls are mocked)
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keyhound.detector import (
    Finding,
    Rule,
    load_rules,
    run_entropy_detection,
    run_regex_detection,
    scan_content,
    scan_multiple,
)
from keyhound.utils import (
    deduplicate_findings,
    finding_fingerprint,
    shannon_entropy,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_JS = base64.b64decode(
    b"LyoqCiAqIHNhbXBsZS5qcyDigJQgU3ludGhldGljIEpTIGZpbGUgdXNlZCBieSBLZXlIb3VuZCB0ZXN0IHN1aXRlLgogKgogKgogKiBDb250YWlucyBkZWxpYmVyYXRlbHkgZW1iZWRkZWQgZmFrZSBjcmVkZW50aWFscyBmb3IgZGV0ZWN0aW9uIHRlc3RpbmcuCiAqIERPIE5PVCB1c2UgYW55IG9mIHRoZXNlIHZhbHVlcyBpbiBwcm9kdWN0aW9uIOKAlCB0aGV5IGFyZSBlbnRpcmVseSBmaWN0aW9uYWwuCiAqLwoKLy8gMS4gQVdTIEFjY2VzcyBLZXkgSUQgKENSSVRJQ0FMIOKAlCByZWdleCBydWxlKQpjb25zdCBBV1NfQUNDRVNTX0tFWSA9ICJBS0lBSU9TRk9ETk43RVhBTVBMRSI7CmNvbnN0IEFXU19TRUNSRVQgPSAid0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWSI7CgovLyAyLiBHaXRIdWIgUGVyc29uYWwgQWNjZXNzIFRva2VuIChDUklUSUNBTCDigJQgcmVnZXggcnVsZSkKY29uc3QgR0lUSFVCX1RPS0VOID0gImdocF9hQmNEZUZnSGlKa0xtTm9QcVJzVHVWd1h5WjEyMzQ1Njc4OTAxMjM0QWIiOwoKLy8gMy4gU3RyaXBlIExpdmUgU2VjcmV0IEtleSAoQ1JJVElDQUwg4oCUIHJlZ2V4IHJ1bGUpCmV4cG9ydCBjb25zdCBzdHJpcGVLZXkgPSAic2tfbGl2ZV81MUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWGFiY2RlZmdoaWprIjsKCi8vIDQuIFNlbmRHcmlkIEFQSSBLZXkgKENSSVRJQ0FMIOKAlCByZWdleCBydWxlKQpjb25zdCBzZW5kZ3JpZEFwaUtleSA9ICJTRy5hYmNkZWZnaGlqa2xtbm9wcXJzdHV2LkFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MGFiY2RlZmdoaWprIjsKCi8vIDUuIFNsYWNrIEJvdCBUb2tlbiAoSElHSCDigJQgcmVnZXggcnVsZSkKd2luZG93Ll9fU0xBQ0tfVE9LRU5fXyA9ICJ4b3hiLTEyMzQ1Njc4OTAxMi0xMjM0NTY3ODkwMTItYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4IjsKCi8vIDYuIEhpZ2gtZW50cm9weSB1bmtub3duIHRva2VuIGluc2lkZSBhbiBhc3NpZ25tZW50IChlbnRyb3B5IHJ1bGUpCmNvbnN0IGFwaUNvbmZpZyA9IHsKICBlbmRwb2ludDogImh0dHBzOi8vYXBpLmludGVybmFsLmV4YW1wbGUuY29tIiwKICBpbnRlcm5hbFNlY3JldDogInhLOSNtUDJAcVI1dlQ4d1kzekE2YkMxZEU0Zkc3aEowIiwKICBzZXNzaW9uVG9rZW46ICJOM3pWdFlGNUdUTjEyUnFYa2JQZTJScDgxTmh6STluZGFsVFEyVEkiLAp9OwoKLy8gNy4gRHVwbGljYXRlIG9mIHRoZSBHaXRIdWIgdG9rZW4gKHNob3VsZCBiZSBkZWR1cGxpY2F0ZWQpCmNvbnN0IGR1cGxpY2F0ZVRva2VuID0gImdocF9hQmNEZUZnSGlKa0xtTm9QcVJzVHVWd1h5WjEyMzQ1Njc4OTAxMjM0QWIiOwoKLy8gSW5ub2NlbnQgdmFyaWFibGUg4oCUIHNob3VsZCBOT1QgYmUgZmxhZ2dlZApjb25zdCB1c2VybmFtZSA9ICJqb2huZG9lIjsKY29uc3QgcGFnZVRpdGxlID0gIldlbGNvbWUgdG8gdGhlIGFwcCI7CgpmdW5jdGlvbiBpbml0QW5hbHl0aWNzKGNvbmZpZykgewogIGNvbnNvbGUubG9nKCJJbml0aWFsaXNpbmcgd2l0aCIsIGNvbmZpZy5lbmRwb2ludCk7Cn0="
).decode("utf-8")
SAMPLE_URL = "https://example.com/static/js/app.js"

# Minimal rule set covering the 5 keys in sample.js
_MINIMAL_RULES = [
    Rule(
        name="AWS Access Key ID",
        provider="AWS",
        severity="CRITICAL",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    Rule(
        name="GitHub Personal Access Token (Classic)",
        provider="GitHub",
        severity="CRITICAL",
        pattern=re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    ),
    Rule(
        name="Stripe Live Secret Key",
        provider="Stripe",
        severity="CRITICAL",
        pattern=re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    ),
    Rule(
        name="SendGrid API Key",
        provider="SendGrid",
        severity="CRITICAL",
        pattern=re.compile(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"),
    ),
    Rule(
        name="Slack Bot Token",
        provider="Slack",
        severity="HIGH",
        pattern=re.compile(
            r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"
        ),
    ),
]


# ── Utility tests ─────────────────────────────────────────────────────────────

class TestShannonEntropy:
    def test_empty_string_returns_zero(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_uniform_string_low_entropy(self) -> None:
        # All same characters → entropy = 0
        assert shannon_entropy("aaaaaaaaaa") == pytest.approx(0.0)

    def test_high_entropy_random_string(self) -> None:
        # A string with diverse characters should have entropy > 3.5
        token = "xK9mP2qR5vT8wY3zA6bC1dE4fG7hJ0!"
        assert shannon_entropy(token) > 3.5

    def test_known_entropy_value(self) -> None:
        # "ab" → each char has p=0.5 → H = 1 bit
        assert shannon_entropy("ab") == pytest.approx(1.0)


class TestFindingFingerprint:
    def test_same_inputs_same_fingerprint(self) -> None:
        fp1 = finding_fingerprint("secret123", "https://example.com/app.js")
        fp2 = finding_fingerprint("secret123", "https://example.com/app.js")
        assert fp1 == fp2

    def test_different_value_different_fingerprint(self) -> None:
        fp1 = finding_fingerprint("secret123", "https://example.com/app.js")
        fp2 = finding_fingerprint("differentSecret", "https://example.com/app.js")
        assert fp1 != fp2

    def test_different_url_different_fingerprint(self) -> None:
        fp1 = finding_fingerprint("secret123", "https://example.com/a.js")
        fp2 = finding_fingerprint("secret123", "https://example.com/b.js")
        assert fp1 != fp2


class TestDeduplication:
    def test_removes_exact_duplicates(self) -> None:
        findings = [
            {
                "rule_name": "Test",
                "provider": "Test",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "matched_value": "secret",
                "file_url": "https://example.com/a.js",
                "line_number": 1,
                "context": "",
                "verified": "NOT_CHECKED",
                "entropy_score": 0.0,
            },
            {
                "rule_name": "Test (duplicate)",
                "provider": "Test",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "matched_value": "secret",          # same value + URL → dup
                "file_url": "https://example.com/a.js",
                "line_number": 5,
                "context": "",
                "verified": "NOT_CHECKED",
                "entropy_score": 0.0,
            },
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1

    def test_keeps_different_values(self) -> None:
        findings = [
            {
                "matched_value": "secret_a",
                "file_url": "https://example.com/a.js",
                "rule_name": "A", "provider": "X", "severity": "HIGH",
                "confidence": "MEDIUM", "line_number": 1, "context": "",
                "verified": "NOT_CHECKED", "entropy_score": 0.0,
            },
            {
                "matched_value": "secret_b",
                "file_url": "https://example.com/a.js",
                "rule_name": "B", "provider": "X", "severity": "HIGH",
                "confidence": "MEDIUM", "line_number": 2, "context": "",
                "verified": "NOT_CHECKED", "entropy_score": 0.0,
            },
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2


# ── Regex detection tests ─────────────────────────────────────────────────────

class TestRegexDetection:
    def test_finds_aws_key(self) -> None:
        results = run_regex_detection(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        providers = [f.provider for f in results]
        assert "AWS" in providers

    def test_finds_github_token(self) -> None:
        results = run_regex_detection(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        providers = [f.provider for f in results]
        assert "GitHub" in providers

    def test_finds_stripe_key(self) -> None:
        results = run_regex_detection(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        providers = [f.provider for f in results]
        assert "Stripe" in providers

    def test_finds_sendgrid_key(self) -> None:
        results = run_regex_detection(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        providers = [f.provider for f in results]
        assert "SendGrid" in providers

    def test_finds_slack_token(self) -> None:
        results = run_regex_detection(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        providers = [f.provider for f in results]
        assert "Slack" in providers

    def test_all_five_providers_detected(self) -> None:
        """Assert all 5 distinct fake keys from sample.js are detected."""
        results = run_regex_detection(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        found_providers = {f.provider for f in results}
        expected = {"AWS", "GitHub", "Stripe", "SendGrid", "Slack"}
        assert expected.issubset(found_providers)

    def test_finding_has_correct_fields(self) -> None:
        results = run_regex_detection(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        for f in results:
            assert isinstance(f, Finding)
            assert f.file_url == SAMPLE_URL
            assert f.line_number >= 1
            assert f.matched_value != ""
            assert f.context != ""

    def test_context_contains_match_line(self) -> None:
        """The context window should include the line with the match."""
        results = run_regex_detection(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        aws_findings = [f for f in results if f.provider == "AWS"]
        assert aws_findings, "AWS finding missing"
        # The matched value should appear in the context
        assert aws_findings[0].matched_value in aws_findings[0].context


# ── Entropy detection tests ───────────────────────────────────────────────────

class TestEntropyDetection:
    def test_flags_high_entropy_token(self) -> None:
        results = run_entropy_detection(SAMPLE_JS, SAMPLE_URL)
        # The internalSecret / sessionToken tokens should be flagged
        assert len(results) > 0, "Entropy engine found no tokens"
        for f in results:
            assert f.provider == "UNKNOWN"
            assert f.severity == "HIGH"
            assert f.entropy_score > 4.0

    def test_does_not_flag_low_entropy(self) -> None:
        low_entropy_content = 'const user = "johndoe";\nconst title = "Welcome";'
        results = run_entropy_detection(low_entropy_content, SAMPLE_URL)
        assert len(results) == 0


# ── Combined scan_content tests ───────────────────────────────────────────────

class TestScanContent:
    def test_deduplication_removes_duplicate_github_token(self) -> None:
        """
        sample.js embeds the GitHub token twice.  After scan_content the
        (matched_value, file_url) fingerprint dedup should return only one
        GitHub finding.
        """
        findings = scan_content(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        github_findings = [f for f in findings if f.provider == "GitHub"]
        assert len(github_findings) == 1, (
            f"Expected 1 GitHub finding after dedup, got {len(github_findings)}"
        )

    def test_findings_sorted_by_severity(self) -> None:
        findings = scan_content(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        severity_order_map = {"CRITICAL": 0, "HIGH": 1, "LOW": 2}
        for i in range(len(findings) - 1):
            a = severity_order_map[findings[i].severity]
            b = severity_order_map[findings[i + 1].severity]
            assert a <= b, (
                f"Findings not sorted: {findings[i].severity} before "
                f"{findings[i + 1].severity}"
            )

    def test_finding_to_dict_serialisable(self) -> None:
        import json
        findings = scan_content(SAMPLE_JS, SAMPLE_URL, _MINIMAL_RULES)
        assert findings, "No findings to serialise"
        d = findings[0].to_dict()
        # Should round-trip through JSON without error
        json_str = json.dumps(d)
        reloaded = json.loads(json_str)
        assert reloaded["rule_name"] == d["rule_name"]


# ── scan_multiple tests ───────────────────────────────────────────────────────

class TestScanMultiple:
    def test_multiple_assets_aggregated(self) -> None:
        assets = [
            {"url": SAMPLE_URL, "content": SAMPLE_JS, "source_type": "external_js"},
            {
                "url": "https://example.com/other.js",
                "content": 'const token = "AKIAIOSFODNN7EXAMPLE";',
                "source_type": "external_js",
            },
        ]
        findings = scan_multiple(assets, _MINIMAL_RULES)
        urls = {f.file_url for f in findings}
        assert SAMPLE_URL in urls
        assert "https://example.com/other.js" in urls

    def test_progress_callback_called(self) -> None:
        assets = [
            {"url": SAMPLE_URL, "content": SAMPLE_JS, "source_type": "external_js"},
        ]
        calls: list[dict] = []
        scan_multiple(assets, _MINIMAL_RULES, progress_callback=calls.append)
        assert len(calls) == 1


# ── Rule loading tests ────────────────────────────────────────────────────────

class TestLoadRules:
    def test_default_rules_load_successfully(self) -> None:
        rules = load_rules()
        assert len(rules) >= 30, f"Expected ≥30 rules, got {len(rules)}"

    def test_rules_have_required_fields(self) -> None:
        rules = load_rules()
        for rule in rules:
            assert rule.name
            assert rule.provider
            assert rule.severity in ("CRITICAL", "HIGH", "LOW")
            assert rule.pattern is not None

    def test_missing_file_raises(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            load_rules(tmp_path / "nonexistent.yaml")

    def test_custom_rules_file(self, tmp_path) -> None:
        custom = tmp_path / "custom.yaml"
        custom.write_text(
            "rules:\n"
            "  - name: Test Rule\n"
            "    provider: Test\n"
            "    severity: HIGH\n"
            "    regex: 'TEST_[A-Z]{8}'\n"
        )
        rules = load_rules(custom)
        assert len(rules) == 1
        assert rules[0].name == "Test Rule"


# ── Verifier mock tests ───────────────────────────────────────────────────────

class TestVerifier:
    """Ensure verifier never makes real network calls during tests."""

    @pytest.mark.asyncio
    async def test_github_verifier_valid(self) -> None:
        from keyhound.verifier import _verify_github

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch(
            "keyhound.verifier._rate_limited_get",
            new=AsyncMock(return_value=mock_response),
        ):
            result = await _verify_github("ghp_faketoken123", mock_client)

        assert result == "VALID"

    @pytest.mark.asyncio
    async def test_github_verifier_expired(self) -> None:
        from keyhound.verifier import _verify_github

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch(
            "keyhound.verifier._rate_limited_get",
            new=AsyncMock(return_value=mock_response),
        ):
            result = await _verify_github("ghp_expiredtoken", mock_client)

        assert result == "EXPIRED"

    @pytest.mark.asyncio
    async def test_stripe_verifier_valid(self) -> None:
        from keyhound.verifier import _verify_stripe

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch(
            "keyhound.verifier._rate_limited_get",
            new=AsyncMock(return_value=mock_response),
        ):
            result = await _verify_stripe("sk_live_fakekey", mock_client)

        assert result == "VALID"

    @pytest.mark.asyncio
    async def test_sendgrid_verifier_expired(self) -> None:
        from keyhound.verifier import _verify_sendgrid

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch(
            "keyhound.verifier._rate_limited_get",
            new=AsyncMock(return_value=mock_response),
        ):
            result = await _verify_sendgrid("SG.fake", mock_client)

        assert result == "EXPIRED"

    @pytest.mark.asyncio
    async def test_slack_verifier_valid(self) -> None:
        from keyhound.verifier import _verify_slack

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ok": True}

        with patch(
            "keyhound.verifier._rate_limited_post",
            new=AsyncMock(return_value=mock_response),
        ):
            result = await _verify_slack("xoxb-fake-token", mock_client)

        assert result == "VALID"

    @pytest.mark.asyncio
    async def test_low_severity_not_checked(self) -> None:
        """LOW findings should always return NOT_CHECKED without API calls."""
        from keyhound.verifier import verify_finding
        import httpx

        finding = Finding(
            rule_name="Generic Secret",
            provider="Generic",
            severity="LOW",
            confidence="LOW",
            matched_value="password123",
            file_url=SAMPLE_URL,
            line_number=1,
            context="",
        )

        # Real client — but NO network call should happen
        async with httpx.AsyncClient() as client:
            result = await verify_finding(finding, client)

        assert result == "NOT_CHECKED"

    @pytest.mark.asyncio
    async def test_unknown_provider_not_checked(self) -> None:
        """Providers with no verifier should return NOT_CHECKED."""
        from keyhound.verifier import verify_finding
        import httpx

        finding = Finding(
            rule_name="Mapbox Token",
            provider="Mapbox",
            severity="HIGH",
            confidence="MEDIUM",
            matched_value="pk.eyJ1abc",
            file_url=SAMPLE_URL,
            line_number=5,
            context="",
        )

        async with httpx.AsyncClient() as client:
            result = await verify_finding(finding, client)

        assert result == "NOT_CHECKED"

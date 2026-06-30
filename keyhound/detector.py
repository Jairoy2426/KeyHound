"""
KeyHound — Detection engine.

Stage 2: Regex pattern matching + Shannon entropy analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from keyhound.utils import (
    deduplicate_findings,
    extract_context,
    extract_high_entropy_tokens,
    finding_fingerprint,
    shannon_entropy,
    severity_order,
)

# Default path to the bundled rules file
_DEFAULT_RULES_PATH = Path(__file__).parent.parent / "rules" / "secrets.yaml"


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """Represents a single secret / high-entropy token detected in a file."""

    rule_name: str
    provider: str
    severity: str          # CRITICAL / HIGH / LOW
    confidence: str        # HIGH / MEDIUM / LOW
    matched_value: str
    file_url: str
    line_number: int
    context: str           # 5-line window around match
    verified: str = "NOT_CHECKED"   # VALID / EXPIRED / UNKNOWN / NOT_CHECKED
    entropy_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise the Finding to a plain dictionary."""
        return {
            "rule_name": self.rule_name,
            "provider": self.provider,
            "severity": self.severity,
            "confidence": self.confidence,
            "matched_value": self.matched_value,
            "file_url": self.file_url,
            "line_number": self.line_number,
            "context": self.context,
            "verified": self.verified,
            "entropy_score": round(self.entropy_score, 4),
        }


# ── Rule loading ───────────────────────────────────────────────────────────────

@dataclass
class Rule:
    """A single secret-detection rule loaded from YAML."""

    name: str
    provider: str
    severity: str
    pattern: re.Pattern[str]


def load_rules(rules_path: Path | str | None = None) -> list[Rule]:
    """
    Load detection rules from a YAML file.

    Args:
        rules_path: Path to a YAML file.  Defaults to ``rules/secrets.yaml``
                    bundled with the package.

    Returns:
        List of compiled :class:`Rule` objects.

    Raises:
        FileNotFoundError: When the rules file does not exist.
        ValueError:        When a rule entry is missing required fields.
    """
    path = Path(rules_path) if rules_path else _DEFAULT_RULES_PATH

    if not path.exists():
        raise FileNotFoundError(f"Rules file not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    rules: list[Rule] = []
    for entry in data.get("rules", []):
        for required in ("name", "provider", "severity", "regex"):
            if required not in entry:
                raise ValueError(
                    f"Rule entry missing required field '{required}': {entry}"
                )
        try:
            pattern = re.compile(entry["regex"])
        except re.error as exc:
            # Skip malformed patterns with a warning rather than crashing
            import warnings
            warnings.warn(
                f"Skipping rule '{entry['name']}' — invalid regex: {exc}",
                stacklevel=2,
            )
            continue

        rules.append(
            Rule(
                name=entry["name"],
                provider=entry["provider"],
                severity=entry["severity"].upper(),
                pattern=pattern,
            )
        )

    return rules


# ── Regex detection ────────────────────────────────────────────────────────────

def _confidence_from_severity(severity: str) -> str:
    """Map a severity label to a default confidence level."""
    return {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "LOW": "LOW"}.get(
        severity.upper(), "LOW"
    )


def run_regex_detection(
    content: str,
    file_url: str,
    rules: list[Rule],
) -> list[Finding]:
    """
    Run all regex rules against *content* and return a list of raw findings
    (before deduplication).

    Args:
        content:  Full text of the file being scanned.
        file_url: URL or path of the file (used for reporting).
        rules:    Compiled rules from :func:`load_rules`.

    Returns:
        List of :class:`Finding` objects.
    """
    findings: list[Finding] = []
    lines = content.splitlines()

    for rule in rules:
        for match in rule.pattern.finditer(content):
            matched_value = match.group(0)
            # Prefer capture group 1 when it exists (the actual secret)
            if match.lastindex and match.lastindex >= 1:
                try:
                    matched_value = match.group(1) or matched_value
                except IndexError:
                    pass

            # Determine which line the match is on (1-based)
            line_number = content[: match.start()].count("\n") + 1
            context = extract_context(content, line_number, window=2)
            entropy = shannon_entropy(matched_value)

            findings.append(
                Finding(
                    rule_name=rule.name,
                    provider=rule.provider,
                    severity=rule.severity,
                    confidence=_confidence_from_severity(rule.severity),
                    matched_value=matched_value,
                    file_url=file_url,
                    line_number=line_number,
                    context=context,
                    entropy_score=entropy,
                )
            )

    return findings


# ── Entropy detection ──────────────────────────────────────────────────────────

def run_entropy_detection(
    content: str,
    file_url: str,
    entropy_threshold: float = 3.5,
) -> list[Finding]:
    """
    Scan *content* for high-entropy string tokens that appear inside JS/JSON
    assignment patterns and return them as findings.

    Args:
        content:           Full text of the file being scanned.
        file_url:          URL or path of the file.
        entropy_threshold: Minimum Shannon entropy to flag a token.

    Returns:
        List of :class:`Finding` objects tagged as provider ``UNKNOWN``.
    """
    findings: list[Finding] = []

    for token, line_number in extract_high_entropy_tokens(content):
        score = shannon_entropy(token)
        if score < entropy_threshold:
            continue

        context = extract_context(content, line_number, window=2)
        findings.append(
            Finding(
                rule_name="High Entropy Token",
                provider="UNKNOWN",
                severity="HIGH",
                confidence="MEDIUM",
                matched_value=token,
                file_url=file_url,
                line_number=line_number,
                context=context,
                entropy_score=score,
            )
        )

    return findings


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_content(
    content: str,
    file_url: str,
    rules: list[Rule],
    entropy_threshold: float = 3.5,
) -> list[Finding]:
    """
    Run both the regex pipeline and entropy analysis against a single piece of
    content, then return deduplicated, severity-sorted findings.

    Args:
        content:           Raw text content of a JS/HTML/JSON file.
        file_url:          Identifying URL or path of the content.
        rules:             Compiled detection rules.
        entropy_threshold: Threshold for flagging high-entropy tokens.

    Returns:
        Sorted, deduplicated list of :class:`Finding` objects.
    """
    raw: list[Finding] = []
    raw.extend(run_regex_detection(content, file_url, rules))
    raw.extend(run_entropy_detection(content, file_url, entropy_threshold))

    # Convert to dicts for deduplication helper, then back to Finding objects
    dicts = [f.to_dict() for f in raw]
    unique_dicts = deduplicate_findings(dicts)

    # Reconstruct Finding objects preserving all fields
    unique_findings = [
        Finding(
            rule_name=d["rule_name"],
            provider=d["provider"],
            severity=d["severity"],
            confidence=d["confidence"],
            matched_value=d["matched_value"],
            file_url=d["file_url"],
            line_number=d["line_number"],
            context=d["context"],
            verified=d["verified"],
            entropy_score=d["entropy_score"],
        )
        for d in unique_dicts
    ]

    # Sort: CRITICAL first, then HIGH, then LOW; within severity by line number
    unique_findings.sort(
        key=lambda f: (severity_order(f.severity), f.line_number)
    )
    return unique_findings


def scan_multiple(
    assets: list[dict[str, str]],
    rules: list[Rule],
    entropy_threshold: float = 3.5,
    progress_callback: Any = None,
) -> list[Finding]:
    """
    Run :func:`scan_content` over a list of asset dicts (as returned by the
    crawler) and aggregate all findings.

    Args:
        assets:            List of ``{url, content, source_type}`` dicts.
        rules:             Compiled detection rules.
        entropy_threshold: Entropy threshold passed to :func:`scan_content`.
        progress_callback: Optional callable(asset_dict) invoked after each
                           asset is scanned (used for progress-bar updates).

    Returns:
        Aggregated, globally deduplicated, sorted list of :class:`Finding`.
    """
    all_findings: list[Finding] = []

    for asset in assets:
        content = asset.get("content", "")
        url = asset.get("url", "<unknown>")
        if content:
            findings = scan_content(content, url, rules, entropy_threshold)
            all_findings.extend(findings)
        if progress_callback:
            progress_callback(asset)

    # Global dedup after combining all assets
    global_dicts = deduplicate_findings([f.to_dict() for f in all_findings])
    result = [
        Finding(
            rule_name=d["rule_name"],
            provider=d["provider"],
            severity=d["severity"],
            confidence=d["confidence"],
            matched_value=d["matched_value"],
            file_url=d["file_url"],
            line_number=d["line_number"],
            context=d["context"],
            verified=d["verified"],
            entropy_score=d["entropy_score"],
        )
        for d in global_dicts
    ]
    result.sort(key=lambda f: (severity_order(f.severity), f.line_number))
    return result

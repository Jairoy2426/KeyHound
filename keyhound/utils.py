"""
KeyHound — Utility functions: entropy calculation, deduplication, and helpers.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Any


# ── Entropy ────────────────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """
    Compute the Shannon entropy (bits per character) of a string.

    Args:
        data: The input string to analyse.

    Returns:
        Entropy value in bits.  Returns 0.0 for empty strings.
    """
    if not data:
        return 0.0

    freq = Counter(data)
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in freq.values()
    )


# ── Deduplication ──────────────────────────────────────────────────────────────

def finding_fingerprint(matched_value: str, file_url: str) -> str:
    """
    Create an MD5 fingerprint for a (matched_value, file_url) pair so that
    duplicate findings from different rule passes can be identified and dropped.

    Args:
        matched_value: The raw secret string that was matched.
        file_url:      The URL / path of the file where the match was found.

    Returns:
        Lowercase hex MD5 digest string.
    """
    raw = f"{matched_value}::{file_url}"
    return hashlib.md5(raw.encode("utf-8", errors="replace")).hexdigest()


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Remove duplicate findings based on (matched_value, file_url) fingerprint.

    Args:
        findings: List of finding dictionaries.

    Returns:
        De-duplicated list preserving first occurrence order.
    """
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []

    for finding in findings:
        fp = finding_fingerprint(
            finding.get("matched_value", ""),
            finding.get("file_url", ""),
        )
        if fp not in seen:
            seen.add(fp)
            unique.append(finding)

    return unique


# ── URL helpers ────────────────────────────────────────────────────────────────

def normalise_url(base: str, href: str) -> str:
    """
    Resolve a potentially relative *href* against a *base* URL.

    Args:
        base: The page URL used as reference.
        href: The href / src attribute value from the HTML.

    Returns:
        Absolute URL string.
    """
    from urllib.parse import urljoin, urlparse

    if not href:
        return ""

    href = href.strip()

    # Already absolute
    if href.startswith(("http://", "https://")):
        return href

    # Protocol-relative
    if href.startswith("//"):
        scheme = urlparse(base).scheme or "https"
        return f"{scheme}:{href}"

    # Everything else — let urljoin handle it
    return urljoin(base, href)


def origin_of(url: str) -> str:
    """Return the scheme + host (+ optional port) of a URL."""
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# ── Context window ─────────────────────────────────────────────────────────────

def extract_context(content: str, line_number: int, window: int = 2) -> str:
    """
    Extract a window of *window* lines before and after *line_number* from
    *content*.

    Args:
        content:     Full file content as a single string.
        line_number: 1-based line number of the match.
        window:      Number of lines to include above and below the match line.

    Returns:
        Multi-line string snippet (at most 2*window + 1 lines).
    """
    lines = content.splitlines()
    zero_idx = line_number - 1
    start = max(0, zero_idx - window)
    end = min(len(lines), zero_idx + window + 1)
    return "\n".join(lines[start:end])


# ── Truncation ─────────────────────────────────────────────────────────────────

def truncate(value: str, max_len: int = 40) -> str:
    """
    Truncate *value* to *max_len* characters, appending '…' when shortened.

    Args:
        value:   Input string.
        max_len: Maximum output length (including the ellipsis character).

    Returns:
        Potentially truncated string.
    """
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


# ── Token extraction & false-positive filtering ────────────────────────────────
#
# Observed false-positive taxonomy (from real-world scans):
#
#   A. SCREAMING_SNAKE_CASE  →  BAILOUT_TO_CLIENT_SIDE_RENDERING
#   B. Any URL               →  https://react.dev/errors/
#   C. GitHub URLs           →  https://github.com/zloirock/core-js
#   D. CSS pseudo-selectors  →  ::view-transition-group(root)
#   E. Tailwind class strs   →  fixed top-0 left-0 right-0 z-50 …
#   F. English prose         →  Aspiring Cybersecurity Professional
#   G. Version strings       →  19.3.0-canary-f93b9fd4-20251217
#   H. Copyright notices     →  © 2014-2024 Denis Pushkarev (zloirock.ru)
#   I. JS operator fragments →  !==ay.protocol&&!a(Ay)?(uy=Ay,i.addEven…
#   J. SVG / XML namespaces  →  http://www.w3.org/2000/svg
#   K. Template backtick str →  `await searchParams`, `searchParams.then`

# JS assignment patterns that could conceal secrets
_ASSIGNMENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""(?:const|let|var)\s+\w+\s*=\s*["']([^"']{20,100})["']"""),
    re.compile(r"""(?<!\w)[\w\-]+\s*:\s*["']([^"']{20,100})["']"""),
    re.compile(r'"[\w\-]+"\s*:\s*"([^"]{20,100})"'),
]

# ── Pre-compiled rejection patterns (cheapest first) ─────────────────────────

# B, C, J — any URL scheme
_FP_URL = re.compile(r"https?://|ftp://|file://|www\.")

# I — JS comparison / logical / arrow operators
_FP_JS_OPS = re.compile(r"!==|===|!=|&&|\|\||\?\.|=>|\?\?|>>|<<|\+\+|--")

# I — JS syntax characters that never appear in a raw secret
_FP_JS_SYNTAX = re.compile(r"[();{}]")

# D — CSS pseudo-element or selector fragments
_FP_CSS_PSEUDO = re.compile(r"^::|:hover|:focus|:nth-|@media|@keyframe")

# A — ALL_CAPS_SNAKE with 2+ underscores (Next.js / React error constants)
_FP_SCREAMING_SNAKE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){2,}$")

# H — copyright / legal text
_FP_COPYRIGHT = re.compile(
    r"\u00a9|&copy;|\(c\)\s+20\d{2}|Copyright\b|All rights reserved",
    re.IGNORECASE,
)

# G — semantic version / build tags (e.g. 19.3.0-canary-f93b9fd4-20251217)
_FP_SEMVER = re.compile(r"\d+\.\d+\.\d+")

# K — template literal remnants
_FP_BACKTICK = re.compile(r"`[^`]+`")

# E / F — consecutive lowercase-word runs separated by spaces or hyphens
# (Tailwind: "fixed top-0 left-0 z-50", prose: "Aspiring Cybersecurity")
_FP_WORD_RUN = re.compile(
    r"(?:[a-zA-Z]{2,}-){2,}|"          # hyphen-run: top-0-left-0-z-50
    r"(?:[a-z]{2,}\s){3,}|"            # space-run:  "fixed top left right"
    r"[A-Z][a-z]{2,}(?:\s[A-Z][a-z]+){2,}"  # Title Case prose: "Aspiring Cyber…"
)

# E — Tailwind responsive / state prefixes (md:, lg:, sm:, hover:, focus:, etc.)
# These always appear in utility CSS class strings, never in real secrets.
_FP_TAILWIND = re.compile(
    r"\b(?:sm|md|lg|xl|2xl|hover|focus|active|group|dark|motion|animate)-"
    r"|opacity-\d|translate-|rotate-|scale-|items-|justify-|flex-|"
    r"rounded-|border-|shadow-|text-|bg-|px-|py-|pt-|pb-|pl-|pr-|p-\d|"
    r"w-\d|h-\d|gap-|m-\d|mt-|mb-|ml-|mr-|min-h-|max-w-|z-\d"
)

# Proxmox / ExtJS - Dotted namespaces (e.g. widget.PVE.qemu.Smbios1InputPanel)
_FP_DOT_NAMESPACE = re.compile(r"^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+){2,}$")

# Proxmox / ExtJS - Widget registration names (e.g. widget.pveQemuProcessorPanel)
_FP_WIDGET = re.compile(r"^(?:widget|PVE)\.[a-zA-Z0-9_]+$", re.IGNORECASE)

# REST API Paths / Routes (e.g. /api2/json/cluster/sdn/vnets?pending=1)
_FP_API_ROUTE = re.compile(r"^/[a-zA-Z0-9_\-/]+(?:\?|\b|$)")

# Base64 Alphabets (common helper/lookup strings in code libraries)
_FP_BASE64_ALPHABET = re.compile(
    r"^[A-Za-z0-9+/=]{60,}$"
)

# HTML markup strings (contains tags or elements)
_FP_HTML_MARKUP = re.compile(r"<[a-zA-Z0-9/]+[^>]*>")

# Code properties/namespaces with camelCase dot access (e.g. axisLayout.combineByIndex)
_FP_CODE_PROPERTY = re.compile(r"^[a-z]+[a-zA-Z0-9_]*\.[A-Za-z0-9_]+$")

# Space-ratio threshold: > 8 % spaces → likely prose / CSS
_FP_SPACE_RATIO = 0.08


def _char_class_count(token: str) -> int:
    """Count how many of [UPPER, lower, digit, symbol] are present in token."""
    return (
        bool(re.search(r"[A-Z]", token))
        + bool(re.search(r"[a-z]", token))
        + bool(re.search(r"[0-9]", token))
        + bool(re.search(r"[^A-Za-z0-9]", token))
    )


def _is_false_positive(token: str) -> bool:
    """
    10-layer false-positive gate for entropy-detected tokens.

    Returns True  → discard  (not a real secret candidate)
    Returns False → keep     (warrants further scrutiny)

    Design principle: each layer targets a *specific* observed FP category.
    Layers are ordered cheapest → most expensive.
    """
    # ── Layer 0: space-density gate ──────────────────────────────────────────
    # Real API keys/tokens are NEVER multi-word strings.
    # If > 10 % of chars are spaces → Tailwind class list or prose.  (E, F)
    if " " in token and token.count(" ") / len(token) > _FP_SPACE_RATIO:
        return True

    # ── Layer 1: URL scheme ───────────────────────────────────────────────────
    # Any token that contains a URL scheme is a URL, not a secret.  (B, C, J)
    if _FP_URL.search(token):
        return True

    # ── Layer 2: JS operator / syntax characters ──────────────────────────────
    # Minified JS code contains comparison / logical operators.  (I)
    if _FP_JS_OPS.search(token):
        return True
    if _FP_JS_SYNTAX.search(token):
        return True

    # ── Layer 3: CSS pseudo-selectors and at-rules ────────────────────────────
    # ::view-transition-group(root) / :hover / @keyframes  (D)
    if _FP_CSS_PSEUDO.search(token):
        return True

    # ── Layer 4: SCREAMING_SNAKE_CASE constants ───────────────────────────────
    # Framework error codes: BAILOUT_TO_CLIENT_SIDE_RENDERING  (A)
    if _FP_SCREAMING_SNAKE.match(token):
        return True

    # ── Layer 5: copyright / legal strings ───────────────────────────────────
    if _FP_COPYRIGHT.search(token):
        return True

    # ── Layer 6: semantic version / build tags ────────────────────────────────
    # 19.3.0-canary-f93b9fd4-20251217  (G)
    if _FP_SEMVER.search(token):
        return True

    # ── Layer 7: template literal backtick remnants ───────────────────────────
    if _FP_BACKTICK.search(token):
        return True

    # ── Layer 8: natural-language word runs ───────────────────────────────────
    # Catches long Tailwind class strings and English prose sentences.  (E, F)
    if _FP_WORD_RUN.search(token):
        return True

    # ── Layer 8b: Tailwind utility-prefix check ───────────────────────────────
    # Catches responsive variants like "md:flex items-center gap-8" that have
    # too few spaces to trip Layer 0 but are unmistakably CSS.  (E)
    if _FP_TAILWIND.search(token):
        return True

    # ── Layer 8c: Proxmox/ExtJS widgets and API routes ────────────────────────
    # Discards ExtJS widget names, dotted namespaces, and REST endpoint routes
    if _FP_DOT_NAMESPACE.match(token):
        return True
    if _FP_WIDGET.match(token):
        return True
    if _FP_API_ROUTE.match(token):
        return True

    # ── Layer 8d: General code and web layout false positives ─────────────────
    if _FP_BASE64_ALPHABET.match(token):
        return True
    if _FP_HTML_MARKUP.search(token):
        return True
    if _FP_CODE_PROPERTY.match(token):
        return True

    # ── Layer 8e: CamelCase English-like variables ────────────────────────────
    # e.g., IP64AddressWithSuffixList, combineDuplicate, pmxAuthLDAPPanel
    # These have uppercase letters but also long runs (5+) of lowercase letters.
    if re.search(r"[A-Z]", token) and re.search(r"[a-z]{5,}", token):
        return True

    # ── Layer 9: character-class diversity ────────────────────────────────────
    # Real secrets always mix at minimum: uppercase + lowercase + digit.
    # A purely-lowercase or purely-uppercase string is almost never a secret.
    if _char_class_count(token) < 3:
        return True

    # ── Layer 10: Space-free density requirement ──────────────────────────────
    # A valid high-entropy secret must be a single dense token.
    # There should never be spaces in raw secrets.
    if " " in token:
        return True

    return False


def extract_high_entropy_tokens(content: str) -> list[tuple[str, int]]:
    """
    Scan *content* for string tokens inside JS/JSON assignment patterns that:

    1. Are 20–80 characters long (real secrets; longer = prose / CSS)
    2. Have Shannon entropy > 4.0  (raised from 3.8 to cut version strings
       which hover at ≈3.8–3.9)
    3. Pass all 10 layers of ``_is_false_positive()``

    Args:
        content: File content (JS, HTML, JSON).

    Returns:
        Deduplicated list of (token_string, 1-based line_number) tuples.
    """
    results: list[tuple[str, int]] = []
    seen: set[str] = set()
    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for pattern in _ASSIGNMENT_PATTERNS:
            for match in pattern.finditer(line):
                token = match.group(1)

                # Length gate — real secrets ≤ 80 chars; longer is usually prose
                if not (20 <= len(token) <= 80):
                    continue

                # Global dedup within this file
                if token in seen:
                    continue

                # Entropy gate (≥ 4.0 bits/char)
                if shannon_entropy(token) <= 4.0:
                    continue

                # False-positive gate (all 10 layers)
                if _is_false_positive(token):
                    continue

                seen.add(token)
                results.append((token, line_no))

    return results


# ── Misc ───────────────────────────────────────────────────────────────────────

def severity_order(severity: str) -> int:
    """Return a sort key for severity so CRITICAL > HIGH > LOW."""
    return {"CRITICAL": 0, "HIGH": 1, "LOW": 2}.get(severity.upper(), 3)

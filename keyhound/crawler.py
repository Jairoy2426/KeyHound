"""
KeyHound — Async HTTP crawler.

Stage 1: Discovers and downloads all JS files, inline scripts, JSON endpoints,
and Webpack / framework chunk files from a target URL.
"""

from __future__ import annotations

import asyncio

# Use lxml when available for speed; fall back to the stdlib html.parser
try:
    import lxml  # noqa: F401
    _BS4_PARSER = "lxml"
except ImportError:
    _BS4_PARSER = "html.parser"
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from keyhound.utils import normalise_url, origin_of

# ── Webpack / bundler chunk patterns ──────────────────────────────────────────

_CHUNK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/static/js/[^\"'<>\s]+\.chunk\.js"),
    re.compile(r"/assets/[^\"'<>\s]+\.js"),
    re.compile(r"/_next/static/chunks/[^\"'<>\s]+\.js"),
    re.compile(r"/build/static/js/[^\"'<>\s]+\.js"),
    re.compile(r"/dist/[^\"'<>\s]+\.js"),
]

# ── Default browser-like headers ──────────────────────────────────────────────

_DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _extract_script_urls(html: str, base_url: str) -> list[str]:
    """Return all external JS URLs found in ``<script src="...">`` tags."""
    soup = BeautifulSoup(html, _BS4_PARSER)
    urls: list[str] = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src:
            full = normalise_url(base_url, src)
            if full:
                urls.append(full)
    return urls


def _extract_inline_scripts(html: str) -> list[str]:
    """Return text content of all inline ``<script>`` blocks."""
    soup = BeautifulSoup(html, _BS4_PARSER)
    blocks: list[str] = []
    for tag in soup.find_all("script", src=False):
        text = tag.get_text()
        if text and text.strip():
            blocks.append(text)
    return blocks


def _extract_json_urls(html: str, base_url: str) -> list[str]:
    """
    Find references to .json or .env files in ``<link>`` / ``<script>`` tags.
    """
    soup = BeautifulSoup(html, _BS4_PARSER)
    urls: list[str] = []
    for tag in soup.find_all(["link", "script"]):
        href = tag.get("href") or tag.get("src") or ""
        if href and (href.endswith(".json") or href.endswith(".env")):
            full = normalise_url(base_url, href)
            if full:
                urls.append(full)
    return urls


def _find_chunk_urls(html_or_js: str, base_url: str) -> list[str]:
    """
    Scan raw text for Webpack chunk-style URL patterns and return absolute
    URLs.
    """
    origin = origin_of(base_url)
    found: list[str] = []
    for pattern in _CHUNK_PATTERNS:
        for match in pattern.finditer(html_or_js):
            path = match.group(0)
            full = f"{origin}{path}"
            found.append(full)
    return found


async def _fetch(
    client: httpx.AsyncClient,
    url: str,
    delay: float = 0.5,
) -> str | None:
    """
    Fetch a single URL and return its text body, or ``None`` on failure.

    Args:
        client: Shared :class:`httpx.AsyncClient` instance.
        url:    URL to fetch.
        delay:  Seconds to sleep before making the request.

    Returns:
        Response body as a string, or ``None`` when the request fails.
    """
    await asyncio.sleep(delay)
    try:
        response = await client.get(url, follow_redirects=True)
        response.raise_for_status()
        return response.text
    except httpx.HTTPStatusError as exc:
        # Non-2xx — silently skip
        return None
    except (httpx.RequestError, Exception):
        return None


# ── Public API ────────────────────────────────────────────────────────────────

async def crawl(
    root_url: str,
    delay: float = 0.5,
    depth: int = 1,
    progress_callback: Any = None,
) -> list[dict[str, str]]:
    """
    Crawl *root_url* and discover all JavaScript files, inline scripts, JSON
    endpoints, and Webpack chunk files.

    Args:
        root_url:          Starting URL to crawl.
        delay:             Seconds to wait between HTTP requests.
        depth:             How many levels deep to follow discovered chunk/JS
                           references (1 = only the root page's direct assets).
        progress_callback: Optional callable(asset_dict) invoked after each
                           asset is fetched (used to drive a progress bar).

    Returns:
        List of dicts:
        ``[{"url": str, "content": str, "source_type": str}]``

        ``source_type`` is one of: ``inline_script``, ``external_js``,
        ``json_file``, ``env_file``.
    """
    assets: list[dict[str, str]] = []
    visited: set[str] = set()

    async with httpx.AsyncClient(
        headers=_DEFAULT_HEADERS,
        timeout=httpx.Timeout(15.0),
        http2=False,         # http2 optional; disabled for wider compat
        verify=False,        # skip TLS verification so self-signed certs work
    ) as client:

        # ── Step 1: fetch root HTML page ─────────────────────────────────────
        html = await _fetch(client, root_url, delay=0)
        if not html:
            return assets
        visited.add(root_url)

        # ── Step 2: inline scripts ─────────────────────────────────────────
        for idx, block in enumerate(_extract_inline_scripts(html)):
            asset: dict[str, str] = {
                "url": f"{root_url}#inline-script-{idx}",
                "content": block,
                "source_type": "inline_script",
            }
            assets.append(asset)
            if progress_callback:
                progress_callback(asset)

        # ── Step 3: build work queue of URLs to download ────────────────────
        to_fetch: list[tuple[str, str]] = []  # (url, source_type)

        for url in _extract_script_urls(html, root_url):
            if url not in visited:
                to_fetch.append((url, "external_js"))

        for url in _extract_json_urls(html, root_url):
            if url not in visited:
                src_type = "env_file" if url.endswith(".env") else "json_file"
                to_fetch.append((url, src_type))

        for url in _find_chunk_urls(html, root_url):
            if url not in visited:
                to_fetch.append((url, "external_js"))

        # ── Step 4: deduplicate and download discovered assets ───────────────
        seen_urls: set[str] = {root_url}
        unique_queue: list[tuple[str, str]] = []
        for url, src in to_fetch:
            if url not in seen_urls:
                seen_urls.add(url)
                unique_queue.append((url, src))

        for url, src_type in unique_queue:
            visited.add(url)
            content = await _fetch(client, url, delay=delay)
            if content is None:
                continue

            asset = {"url": url, "content": content, "source_type": src_type}
            assets.append(asset)
            if progress_callback:
                progress_callback(asset)

            # ── Step 5: deeper chunk discovery (depth > 1) ───────────────────
            if depth > 1 and src_type == "external_js":
                for chunk_url in _find_chunk_urls(content, root_url):
                    if chunk_url not in visited:
                        visited.add(chunk_url)
                        chunk_content = await _fetch(
                            client, chunk_url, delay=delay
                        )
                        if chunk_content:
                            chunk_asset = {
                                "url": chunk_url,
                                "content": chunk_content,
                                "source_type": "external_js",
                            }
                            assets.append(chunk_asset)
                            if progress_callback:
                                progress_callback(chunk_asset)

    return assets


async def crawl_file(local_path: str) -> list[dict[str, str]]:
    """
    Read a local JS or HTML file and return it as a single-item asset list.

    Args:
        local_path: Absolute or relative path to a local file.

    Returns:
        List with one ``{"url", "content", "source_type"}`` dict.
    """
    from pathlib import Path

    path = Path(local_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {local_path}")

    content = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()

    if suffix in (".html", ".htm"):
        # Extract inline scripts and return them individually
        assets: list[dict[str, str]] = []
        for idx, block in enumerate(_extract_inline_scripts(content)):
            assets.append(
                {
                    "url": f"file://{path.resolve()}#inline-script-{idx}",
                    "content": block,
                    "source_type": "inline_script",
                }
            )
        # Also include the raw HTML for regex matching
        assets.append(
            {
                "url": f"file://{path.resolve()}",
                "content": content,
                "source_type": "external_js",
            }
        )
        return assets

    src_type = "json_file" if suffix == ".json" else "external_js"
    return [
        {
            "url": f"file://{path.resolve()}",
            "content": content,
            "source_type": src_type,
        }
    ]

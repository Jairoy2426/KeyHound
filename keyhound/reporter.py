"""
KeyHound — Output reporters.

Supports three modes:
  1. Terminal  — rich table + summary panel (always shown)
  2. JSON      — pretty-printed file in reports/
  3. HTML      — self-contained dark-theme report in reports/
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from keyhound.detector import Finding

_REPORTS_DIR = Path("reports")

console = Console()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _truncate(value: str, max_len: int = 40) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


def _severity_colour(severity: str, verified: str) -> str:
    """Map severity + verified status to a rich colour name."""
    if severity == "CRITICAL" and verified == "VALID":
        return "bold red"
    if severity == "CRITICAL":
        return "red"
    if severity == "HIGH":
        return "yellow"
    return "dim"


def _verified_badge(status: str) -> Text:
    """Return a coloured rich Text badge for a verification status."""
    colours = {
        "VALID": "bold green",
        "EXPIRED": "dim green",
        "UNKNOWN": "dim",
        "NOT_CHECKED": "dim",
    }
    return Text(status, style=colours.get(status, "dim"))


# ── Terminal reporter ─────────────────────────────────────────────────────────

def print_table(
    findings: list["Finding"],
    scanned_count: int = 0,
) -> None:
    """
    Print a rich terminal table of all findings plus a summary panel.

    Args:
        findings:      List of :class:`~keyhound.detector.Finding` objects.
        scanned_count: Number of files / assets that were scanned.
    """
    if not findings:
        console.print(
            Panel(
                "[bold green]✓ No secrets found.[/bold green]",
                title="[bold]KeyHound[/bold]",
                border_style="green",
            )
        )
        return

    table = Table(
        title="[bold red]🐾 KeyHound — Secret Findings[/bold red]",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
        expand=True,
    )

    table.add_column("Severity", style="bold", min_width=9, justify="center")
    table.add_column("Provider", min_width=10)
    table.add_column("Rule", min_width=22)
    table.add_column("File", min_width=30, overflow="fold")
    table.add_column("Line", min_width=5, justify="right")
    table.add_column("Verified", min_width=11, justify="center")
    table.add_column("Value (truncated)", min_width=30, overflow="fold")

    for f in findings:
        colour = _severity_colour(f.severity, f.verified)
        row_style = (
            "on dark_red" if (f.severity == "CRITICAL" and f.verified == "VALID")
            else ""
        )

        table.add_row(
            Text(f.severity, style=colour),
            Text(f.provider),
            Text(f.rule_name),
            Text(_truncate(f.file_url, 50)),
            Text(str(f.line_number)),
            _verified_badge(f.verified),
            Text(_truncate(f.matched_value, 40), style="cyan"),
            style=row_style,
        )

    console.print(table)

    # ── Summary panel ──────────────────────────────────────────────────────
    valid_count = sum(1 for f in findings if f.verified == "VALID")
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")

    summary_lines = [
        f"[bold]Files scanned:[/bold]    {scanned_count}",
        f"[bold]Total findings:[/bold]   {len(findings)}",
        f"[red]CRITICAL:[/red]          {critical_count}",
        f"[yellow]HIGH:[/yellow]              {high_count}",
        f"[green]Verified VALID:[/green]    {valid_count}",
    ]

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold]Scan Summary[/bold]",
            border_style="blue",
            expand=False,
        )
    )


# ── JSON reporter ─────────────────────────────────────────────────────────────

def write_json(
    findings: list["Finding"],
    scanned_count: int = 0,
    output_path: Path | None = None,
) -> Path:
    """
    Write all findings to a pretty-printed JSON file.

    Args:
        findings:      List of :class:`~keyhound.detector.Finding` objects.
        scanned_count: Number of files / assets that were scanned.
        output_path:   Override the default output path.

    Returns:
        :class:`pathlib.Path` of the written file.
    """
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = output_path or _REPORTS_DIR / f"keyhound_{_timestamp()}.json"

    payload = {
        "meta": {
            "tool": "KeyHound",
            "version": "1.0.0",
            "generated_at": datetime.now().isoformat(),
            "files_scanned": scanned_count,
            "total_findings": len(findings),
        },
        "findings": [f.to_dict() for f in findings],
    }

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print(f"[bold green]✓ JSON report saved:[/bold green] {path}")
    return path


# ── HTML reporter ─────────────────────────────────────────────────────────────

def _severity_badge_html(severity: str, verified: str) -> str:
    colours = {
        "CRITICAL": "#ff4d4d",
        "HIGH": "#ffaa00",
        "LOW": "#888888",
    }
    colour = colours.get(severity, "#888888")
    glow = (
        f"box-shadow: 0 0 8px {colour};"
        if (severity == "CRITICAL" and verified == "VALID")
        else ""
    )
    return (
        f'<span class="badge" style="background:{colour};{glow}">'
        f'{severity}</span>'
    )


def _verified_badge_html(status: str) -> str:
    colours = {
        "VALID": "#00cc66",
        "EXPIRED": "#888888",
        "UNKNOWN": "#555555",
        "NOT_CHECKED": "#444444",
    }
    colour = colours.get(status, "#444444")
    return f'<span class="badge" style="background:{colour}">{status}</span>'


def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


def _finding_card_html(f: "Finding") -> str:
    border_colour = {
        "CRITICAL": "#ff4d4d",
        "HIGH": "#ffaa00",
        "LOW": "#666666",
    }.get(f.severity, "#666666")

    context_escaped = _escape_html(f.context)

    return f"""
    <div class="card" style="border-left-color:{border_colour}">
      <div class="card-header">
        {_severity_badge_html(f.severity, f.verified)}
        {_verified_badge_html(f.verified)}
        <span class="provider">{_escape_html(f.provider)}</span>
        <span class="rule-name">{_escape_html(f.rule_name)}</span>
      </div>
      <div class="card-meta">
        <span class="label">File:</span>
        <span class="file-url">{_escape_html(f.file_url)}</span>
        <span class="label">Line:</span>
        <span>{f.line_number}</span>
        <span class="label">Entropy:</span>
        <span>{f.entropy_score:.3f}</span>
        <span class="label">Confidence:</span>
        <span>{_escape_html(f.confidence)}</span>
      </div>
      <div class="matched-value">
        <span class="label">Matched:</span>
        <code>{_escape_html(f.matched_value)}</code>
      </div>
      <pre class="context"><code>{context_escaped}</code></pre>
    </div>
    """


def write_html(
    findings: list["Finding"],
    scanned_count: int = 0,
    target_url: str = "",
    output_path: Path | None = None,
) -> Path:
    """
    Write a self-contained dark-theme HTML report.

    Args:
        findings:      List of :class:`~keyhound.detector.Finding` objects.
        scanned_count: Number of files / assets that were scanned.
        target_url:    The URL that was scanned (for the report header).
        output_path:   Override the default output path.

    Returns:
        :class:`pathlib.Path` of the written file.
    """
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = output_path or _REPORTS_DIR / f"keyhound_{_timestamp()}.html"

    valid_count = sum(1 for f in findings if f.verified == "VALID")
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    cards_html = "\n".join(_finding_card_html(f) for f in findings)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>KeyHound Report — {_escape_html(target_url or 'Local Scan')}</title>
  <meta name="description" content="KeyHound secret detection scan report" />
  <style>
    :root {{
      --bg: #0d1117;
      --surface: #161b22;
      --surface2: #21262d;
      --border: #30363d;
      --text: #c9d1d9;
      --text-dim: #8b949e;
      --accent: #58a6ff;
      --red: #ff4d4d;
      --yellow: #ffaa00;
      --green: #3fb950;
      --font: 'Segoe UI', system-ui, sans-serif;
      --mono: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    }}
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
    }}
    /* ── Header ── */
    .header {{
      background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
      border-bottom: 1px solid var(--border);
      padding: 32px 48px;
    }}
    .header h1 {{
      font-size: 28px;
      font-weight: 700;
      color: var(--accent);
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 6px;
    }}
    .header .subtitle {{
      color: var(--text-dim);
      font-size: 13px;
    }}
    .header .target-url {{
      color: var(--text);
      word-break: break-all;
      margin-top: 4px;
      font-family: var(--mono);
      font-size: 12px;
    }}
    /* ── Stats bar ── */
    .stats-bar {{
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      padding: 20px 48px;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
    }}
    .stat-card {{
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 24px;
      min-width: 120px;
      text-align: center;
    }}
    .stat-card .value {{
      font-size: 28px;
      font-weight: 700;
      display: block;
    }}
    .stat-card .label {{
      font-size: 11px;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }}
    .stat-card.critical .value {{ color: var(--red); }}
    .stat-card.high .value {{ color: var(--yellow); }}
    .stat-card.valid .value {{ color: var(--green); }}
    .stat-card.total .value {{ color: var(--accent); }}
    /* ── Findings container ── */
    .findings {{
      padding: 32px 48px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }}
    .findings-title {{
      font-size: 16px;
      font-weight: 600;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 8px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }}
    /* ── Finding card ── */
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-left: 4px solid transparent;
      border-radius: 8px;
      padding: 16px 20px;
      transition: box-shadow 0.2s;
    }}
    .card:hover {{
      box-shadow: 0 0 0 1px var(--border), 0 4px 16px rgba(0,0,0,0.4);
    }}
    .card-header {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 10px;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 10px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #fff;
    }}
    .provider {{
      font-weight: 600;
      color: var(--accent);
      font-size: 13px;
    }}
    .rule-name {{
      color: var(--text-dim);
      font-size: 13px;
    }}
    .card-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px 16px;
      font-size: 12px;
      color: var(--text-dim);
      margin-bottom: 10px;
    }}
    .label {{
      font-weight: 600;
      color: var(--text-dim);
    }}
    .file-url {{
      font-family: var(--mono);
      color: var(--text);
      word-break: break-all;
    }}
    .matched-value {{
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      margin-bottom: 10px;
      font-size: 12px;
      display: flex;
      align-items: flex-start;
      gap: 10px;
      overflow-x: auto;
    }}
    .matched-value code {{
      font-family: var(--mono);
      color: #e06c75;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    .context {{
      background: #010409;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      overflow-x: auto;
      font-size: 12px;
    }}
    .context code {{
      font-family: var(--mono);
      color: var(--text);
      white-space: pre;
    }}
    /* ── Empty state ── */
    .empty-state {{
      text-align: center;
      padding: 80px 20px;
      color: var(--text-dim);
    }}
    .empty-state .icon {{ font-size: 48px; margin-bottom: 16px; }}
    /* ── Footer ── */
    .footer {{
      text-align: center;
      padding: 24px;
      color: var(--text-dim);
      font-size: 12px;
      border-top: 1px solid var(--border);
      margin-top: 32px;
    }}
    @media (max-width: 700px) {{
      .header, .stats-bar, .findings {{ padding-left: 16px; padding-right: 16px; }}
      .stats-bar {{ gap: 8px; }}
    }}
  </style>
</head>
<body>

<header class="header">
  <h1>🐾 KeyHound</h1>
  <p class="subtitle">Secret Detection Report &mdash; Generated {generated_at}</p>
  {f'<p class="target-url">Target: {_escape_html(target_url)}</p>' if target_url else ''}
</header>

<section class="stats-bar">
  <div class="stat-card total">
    <span class="value">{scanned_count}</span>
    <span class="label">Files Scanned</span>
  </div>
  <div class="stat-card total">
    <span class="value">{len(findings)}</span>
    <span class="label">Total Findings</span>
  </div>
  <div class="stat-card critical">
    <span class="value">{critical_count}</span>
    <span class="label">Critical</span>
  </div>
  <div class="stat-card high">
    <span class="value">{high_count}</span>
    <span class="label">High</span>
  </div>
  <div class="stat-card">
    <span class="value" style="color:var(--text-dim)">{low_count}</span>
    <span class="label">Low</span>
  </div>
  <div class="stat-card valid">
    <span class="value">{valid_count}</span>
    <span class="label">Verified Valid</span>
  </div>
</section>

<main class="findings">
  <p class="findings-title">Findings ({len(findings)})</p>
  {''.join([_finding_card_html(f) for f in findings]) if findings else
   '<div class="empty-state"><div class="icon">✅</div><p>No secrets detected.</p></div>'}
</main>

<footer class="footer">
  KeyHound v1.0.0 &mdash; For authorised security testing only.
  Do not use against systems you do not own or have explicit permission to test.
</footer>

</body>
</html>
"""

    path.write_text(html, encoding="utf-8")
    console.print(f"[bold green]✓ HTML report saved:[/bold green] {path}")
    return path

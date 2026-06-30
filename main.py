"""
KeyHound — CLI entry point.

Usage examples:
  python main.py scan https://example.com
  python main.py scan https://example.com --no-verify --json --html
  python main.py file path/to/app.js --html
  python main.py rules
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.text import Text

from keyhound import __version__
from keyhound.crawler import crawl, crawl_file
from keyhound.detector import Finding, load_rules, scan_multiple
from keyhound.reporter import print_table, write_html, write_json
from keyhound.verifier import verify_findings

app = typer.Typer(
    name="keyhound",
    help="🐾 KeyHound — 3-stage secret detection for frontend assets.",
    add_completion=False,
)

console = Console()

# ── ASCII banner ───────────────────────────────────────────────────────────────

_BANNER = r"""
 _  __          _   _                       _
| |/ /___ _   _| | | | ___  _   _ _ __   __| |
| ' // _ \ | | | |_| |/ _ \| | | | '_ \ / _` |
| . \  __/ |_| |  _  | (_) | |_| | | | | (_| |
|_|\_\___|\__, |_| |_|\___/ \__,_|_| |_|\__,_|
          |___/       v{version}  🐾 Secret Hunter
"""


def _print_banner() -> None:
    console.print(
        Panel(
            Text(_BANNER.format(version=__version__), style="bold cyan"),
            border_style="dim blue",
            expand=False,
        )
    )


# ── Shared options ─────────────────────────────────────────────────────────────

def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]KeyHound[/bold cyan] v{__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
    """KeyHound — secret detection pipeline for frontend assets."""


# ── `scan` command ─────────────────────────────────────────────────────────────

@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to crawl and scan."),
    no_verify: bool = typer.Option(
        False, "--no-verify", help="Skip Stage 3 live API verification."
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Save findings to a JSON file in reports/."
    ),
    html_out: bool = typer.Option(
        False, "--html", help="Save a self-contained HTML report in reports/."
    ),
    delay: float = typer.Option(
        0.5, "--delay", help="Seconds to wait between HTTP requests."
    ),
    depth: int = typer.Option(
        1, "--depth", help="Crawl depth for chunk discovery."
    ),
    custom_rules: Optional[str] = typer.Option(
        None,
        "--custom-rules",
        help="Path to a custom secrets YAML rules file.",
    ),
) -> None:
    """
    Full 3-stage pipeline: crawl → detect → verify → report.
    """
    _print_banner()

    # ── Load rules ──────────────────────────────────────────────────────────
    rules_path = Path(custom_rules) if custom_rules else None
    try:
        rules = load_rules(rules_path)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    console.print(
        f"[dim]Loaded [bold]{len(rules)}[/bold] detection rules.[/dim]"
    )

    # ── Stage 1: Crawl ───────────────────────────────────────────────────────
    console.print(f"\n[bold blue]Stage 1 — Crawling:[/bold blue] {url}")

    assets: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        crawl_task = progress.add_task(
            "[cyan]Fetching assets…", total=None
        )

        def on_asset_fetched(asset: dict) -> None:
            nonlocal assets
            progress.advance(crawl_task)
            progress.update(
                crawl_task,
                description=(
                    f"[cyan]Fetched [dim]{asset['source_type']}[/dim]: "
                    f"{asset['url'][-60:]}"
                ),
            )

        assets = asyncio.run(
            crawl(url, delay=delay, depth=depth, progress_callback=on_asset_fetched)
        )

    console.print(
        f"[green]✓[/green] Crawled [bold]{len(assets)}[/bold] asset(s)."
    )

    if not assets:
        console.print("[yellow]Warning:[/yellow] No assets discovered. Exiting.")
        raise typer.Exit(0)

    # ── Stage 2: Detect ──────────────────────────────────────────────────────
    console.print(f"\n[bold blue]Stage 2 — Scanning {len(assets)} asset(s)…[/bold blue]")

    findings: list[Finding] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        scan_task = progress.add_task(
            "[magenta]Scanning…", total=len(assets)
        )

        def on_asset_scanned(asset: dict) -> None:
            progress.advance(scan_task)
            progress.update(
                scan_task,
                description=(
                    f"[magenta]Scanned [dim]{asset.get('source_type', '')}[/dim]: "
                    f"{asset.get('url', '')[-55:]}"
                ),
            )

        findings = scan_multiple(
            assets,
            rules=rules,
            progress_callback=on_asset_scanned,
        )

    console.print(
        f"[green]✓[/green] Detection complete — "
        f"[bold]{len(findings)}[/bold] finding(s) before verification."
    )

    # ── Stage 3: Verify ──────────────────────────────────────────────────────
    if not no_verify and findings:
        eligible = [
            f for f in findings if f.severity in ("CRITICAL", "HIGH")
        ]
        console.print(
            f"\n[bold blue]Stage 3 — Verifying "
            f"{len(eligible)} high-confidence finding(s)…[/bold blue]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            verify_task = progress.add_task(
                "[yellow]Verifying…", total=len(findings)
            )

            def on_verified(finding: Finding) -> None:
                progress.advance(verify_task)
                progress.update(
                    verify_task,
                    description=(
                        f"[yellow]Verified [dim]{finding.provider}[/dim] — "
                        f"{finding.verified}"
                    ),
                )

            findings = asyncio.run(
                verify_findings(findings, progress_callback=on_verified)
            )

        valid_count = sum(1 for f in findings if f.verified == "VALID")
        console.print(
            f"[green]✓[/green] Verification complete — "
            f"[bold red]{valid_count}[/bold red] key(s) confirmed VALID."
        )
    else:
        if no_verify:
            console.print("\n[dim]Skipping verification (--no-verify).[/dim]")

    # ── Output ────────────────────────────────────────────────────────────────
    console.print()
    print_table(findings, scanned_count=len(assets))

    if json_out:
        write_json(findings, scanned_count=len(assets))

    if html_out:
        write_html(findings, scanned_count=len(assets), target_url=url)


# ── `file` command ─────────────────────────────────────────────────────────────

@app.command(name="file")
def scan_file(
    path: str = typer.Argument(..., help="Path to a local JS, HTML, or JSON file."),
    no_verify: bool = typer.Option(
        False, "--no-verify", help="Skip Stage 3 live API verification."
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Save findings to a JSON file in reports/."
    ),
    html_out: bool = typer.Option(
        False, "--html", help="Save a self-contained HTML report in reports/."
    ),
    custom_rules: Optional[str] = typer.Option(
        None,
        "--custom-rules",
        help="Path to a custom secrets YAML rules file.",
    ),
) -> None:
    """
    Scan a single local JS, HTML, or JSON file (no crawling).
    """
    _print_banner()

    rules_path = Path(custom_rules) if custom_rules else None
    try:
        rules = load_rules(rules_path)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    console.print(f"[dim]Loaded [bold]{len(rules)}[/bold] detection rules.[/dim]")

    # Read local file
    try:
        assets = asyncio.run(crawl_file(path))
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    console.print(
        f"[green]✓[/green] Loaded [bold]{len(assets)}[/bold] content block(s) "
        f"from [cyan]{path}[/cyan]."
    )

    # Detect
    findings = scan_multiple(assets, rules=rules)
    console.print(
        f"[green]✓[/green] [bold]{len(findings)}[/bold] finding(s) detected."
    )

    # Verify
    if not no_verify and findings:
        findings = asyncio.run(verify_findings(findings))

    # Report
    print_table(findings, scanned_count=len(assets))

    if json_out:
        write_json(findings, scanned_count=len(assets))

    if html_out:
        write_html(findings, scanned_count=len(assets), target_url=f"file://{path}")


# ── `rules` command ────────────────────────────────────────────────────────────

@app.command()
def rules(
    custom_rules: Optional[str] = typer.Option(
        None,
        "--custom-rules",
        help="Path to a custom secrets YAML rules file.",
    ),
) -> None:
    """
    List all loaded detection rules.
    """
    rules_path = Path(custom_rules) if custom_rules else None
    try:
        loaded = load_rules(rules_path)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    from rich import box
    from rich.table import Table

    table = Table(
        title=f"[bold]KeyHound — Loaded Rules ({len(loaded)})[/bold]",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Name", min_width=28)
    table.add_column("Provider", min_width=12)
    table.add_column("Severity", min_width=10, justify="center")
    table.add_column("Pattern (truncated)", min_width=40, overflow="fold")

    severity_colours = {
        "CRITICAL": "bold red",
        "HIGH": "yellow",
        "LOW": "dim",
    }

    for idx, rule in enumerate(loaded, start=1):
        pattern_str = rule.pattern.pattern
        if len(pattern_str) > 55:
            pattern_str = pattern_str[:54] + "…"

        table.add_row(
            str(idx),
            rule.name,
            rule.provider,
            Text(rule.severity, style=severity_colours.get(rule.severity, "")),
            Text(pattern_str, style="dim cyan"),
        )

    console.print(table)


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()

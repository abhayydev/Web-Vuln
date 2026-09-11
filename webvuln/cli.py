"""Professional Rich-powered Command-Line Interface for WebVuln Scanner."""

import asyncio
import sys
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from webvuln import __version__
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.orchestrator import ScannerOrchestrator
from webvuln.core.target import TargetValidator, TargetValidationError
from webvuln.discovery.crawler import Crawler
from webvuln.fingerprint.technologies import TechnologyFingerprinter
from webvuln.models.request import DiscoveredRequest
from webvuln.scanners.api import APIScanner

app = typer.Typer(
    name="webvuln",
    help="WebVuln Scanner — Advanced Automated Web Vulnerability Assessment Framework",
    add_completion=False,
)
console = Console(force_terminal=True, legacy_windows=False)

ASCII_BANNER = f"""[bold cyan]
 __      __      ___.   ____   ____      .__           
/  \\    /  \\ ____\\_ |___\\   \\ /   /_ __  |  |   ____  
\\   \\/\\/   // __ \\| __ \\ \\   Y   /  |  \\ |  |  /    \\ 
 \\        /\\  ___/| \\_\\ \\ \\     /|  |  / |  |_|   |  \\
  \\__/\\  /  \\___  >___  /  \\___/ |____/  |____/___|  /
       \\/       \\/    \\/                           \\/ 
[/bold cyan]
[bold white]WebVuln Scanner v{__version__}[/bold white] — [dim]Educational & Authorized VAPT Engine[/dim]
"""

WARNING_DISCLAIMER = """[bold red]LEGAL & ETHICAL WARNING:[/bold red]
This tool is strictly designed for educational testing, CTF challenges,
localhost lab environments, and systems where you have [bold yellow]explicit, written authorization[/bold yellow].
Scanning unauthorized targets violates computer crime laws."""


def print_banner():
    """Prints the application banner and legal notice."""
    console.print(ASCII_BANNER)
    console.print(Panel(WARNING_DISCLAIMER, border_style="red"))


@app.command(name="scan")
def scan_cmd(
    target: str = typer.Argument(..., help="Target URL to scan (e.g. http://localhost:8080 or https://lab.local)"),
    depth: int = typer.Option(3, "--depth", "-d", help="Max crawl depth"),
    max_urls: int = typer.Option(50, "--max-urls", help="Max URLs to discover and scan"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Max concurrent requests"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="HTTP timeout in seconds"),
    scope: Optional[List[str]] = typer.Option(None, "--scope", "-s", help="Additional allowed in-scope domains"),
    checks: Optional[str] = typer.Option(None, "--checks", help="Comma-separated list of check modules to run"),
    output: Path = typer.Option(Path("reports"), "--output", "-o", help="Output directory for reports"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging"),
):
    """Run full automated vulnerability scan on a target."""
    print_banner()

    try:
        custom_scope = set(scope) if scope else set()
        validated_target = TargetValidator.validate_and_parse(target, custom_scope)
    except TargetValidationError as e:
        console.print(f"[bold red]Target Validation Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    checks_list = [c.strip() for c in checks.split(",")] if checks else ScanConfig(target_url=validated_target.normalized_url).checks

    config = ScanConfig(
        target_url=validated_target.normalized_url,
        scope_domains=set(validated_target.allowed_scope),
        max_depth=depth,
        max_urls=max_urls,
        concurrency=concurrency,
        timeout=timeout,
        checks=checks_list,
        output_dir=output,
        verbose=verbose,
    )

    orchestrator = ScannerOrchestrator(validated_target, config)
    result = asyncio.run(orchestrator.execute_scan())

    # Render Terminal Findings Summary Dashboard
    summary_table = Table(title="Assessment Summary Dashboard", border_style="cyan")
    summary_table.add_column("Metric", style="bold white")
    summary_table.add_column("Value", style="green")

    summary_table.add_row("Target URL", result.target.normalized_url)
    summary_table.add_row("Total HTTP Requests", str(result.summary.total_requests))
    summary_table.add_row("Discovered Endpoints", str(len(result.endpoints)))
    summary_table.add_row("Total Findings", str(len(result.findings)))
    summary_table.add_row("Overall Risk Rating", f"{result.summary.overall_risk_score} / 10.0")
    summary_table.add_row("Duration", f"{result.summary.duration_seconds}s")
    console.print(summary_table)

    # Severity Breakdown Table
    sev_table = Table(title="Vulnerabilities by Severity", border_style="cyan")
    sev_table.add_column("Severity Level", style="bold")
    sev_table.add_column("Count", justify="center")

    sev_table.add_row("[bold red]CRITICAL[/bold red]", str(result.summary.critical_count))
    sev_table.add_row("[bold orange3]HIGH[/bold orange3]", str(result.summary.high_count))
    sev_table.add_row("[bold yellow]MEDIUM[/bold yellow]", str(result.summary.medium_count))
    sev_table.add_row("[bold blue]LOW[/bold blue]", str(result.summary.low_count))
    sev_table.add_row("[bold cyan]INFO[/bold cyan]", str(result.summary.info_count))
    console.print(sev_table)

    if result.findings:
        findings_table = Table(title=f"Detailed Findings ({len(result.findings)})", border_style="cyan")
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Title", style="bold white")
        findings_table.add_column("Endpoint", style="dim white")
        findings_table.add_column("Confidence", style="cyan", width=12)

        for f in result.findings:
            sev_style = "bold red" if f.severity.value == "CRITICAL" else ("orange3" if f.severity.value == "HIGH" else "yellow")
            findings_table.add_row(f"[{sev_style}]{f.severity.value}[/{sev_style}]", f.title, f.url, f.confidence.value)
        console.print(findings_table)

    console.print(f"\n[bold green][+] HTML Report:[/bold green] file:///{config.output_dir.resolve() / 'scan.html'}")
    console.print(f"[bold green][+] JSON Report:[/bold green] file:///{config.output_dir.resolve() / 'scan.json'}\n")


@app.command(name="api")
def api_cmd(
    target: str = typer.Argument(..., help="Target API URL (e.g. http://localhost:8080 or http://localhost:8080/api)"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="HTTP timeout in seconds"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging"),
):
    """Audit REST API endpoints, OpenAPI/Swagger specifications, and JSON schemas."""
    print_banner()

    try:
        validated_target = TargetValidator.validate_and_parse(target)
    except TargetValidationError as e:
        console.print(f"[bold red]Target Validation Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    config = ScanConfig(target_url=validated_target.normalized_url, timeout=timeout, verbose=verbose)
    endpoint = DiscoveredRequest(url=validated_target.normalized_url)

    async def _run_api():
        async with ScanContext(config) as ctx:
            scanner = APIScanner()
            return await scanner.scan(validated_target, ctx, endpoint)

    findings = asyncio.run(_run_api())

    if not findings:
        console.print("[green][+] No immediate API misconfigurations or exposed OpenAPI schemas observed.[/green]")
        return

    table = Table(title=f"API Security Audit Findings ({len(findings)})", border_style="cyan")
    table.add_column("Severity", style="bold red", width=12)
    table.add_column("Title", style="bold white")
    table.add_column("Evidence", style="green")

    for f in findings:
        table.add_row(f.severity.value, f.title, f.evidence)

    console.print(table)


@app.command(name="fingerprint")
def fingerprint_cmd(
    target: str = typer.Argument(..., help="Target URL to fingerprint (e.g. http://localhost:8080)"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="HTTP timeout in seconds"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging"),
):
    """Passively fingerprint web server, backend framework, and frontend technologies."""
    print_banner()

    try:
        validated_target = TargetValidator.validate_and_parse(target)
    except TargetValidationError as e:
        console.print(f"[bold red]Target Validation Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    config = ScanConfig(target_url=validated_target.normalized_url, timeout=timeout, verbose=verbose)

    async def _run_fp():
        async with ScanContext(config) as ctx:
            return await TechnologyFingerprinter.fingerprint_target(validated_target.normalized_url, ctx)

    tech_results = asyncio.run(_run_fp())

    if not tech_results:
        console.print("[yellow][!] No distinct technologies could be identified from target response headers/body.[/yellow]")
        return

    table = Table(title=f"Fingerprinted Technologies for {validated_target.normalized_url}", border_style="cyan")
    table.add_column("Technology", style="bold white")
    table.add_column("Confidence Score", style="bold green", width=20)

    for tech, conf in sorted(tech_results.items(), key=lambda x: x[1], reverse=True):
        conf_pct = f"{int(conf * 100)}%"
        table.add_row(tech, conf_pct)

    console.print(table)


@app.command(name="crawl")
def crawl_cmd(
    target: str = typer.Argument(..., help="Target URL to crawl (e.g. http://localhost:8080)"),
    depth: int = typer.Option(3, "--depth", "-d", help="Max crawl depth"),
    max_urls: int = typer.Option(50, "--max-urls", help="Max URLs to discover"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Max concurrent requests"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="HTTP timeout in seconds"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging"),
):
    """Crawl a target to discover links, forms, parameters, and API endpoints."""
    print_banner()

    try:
        validated_target = TargetValidator.validate_and_parse(target)
    except TargetValidationError as e:
        console.print(f"[bold red]Target Validation Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    config = ScanConfig(
        target_url=validated_target.normalized_url,
        scope_domains=set(validated_target.allowed_scope),
        max_depth=depth,
        max_urls=max_urls,
        concurrency=concurrency,
        timeout=timeout,
        verbose=verbose,
    )

    async def _run_crawl():
        async with ScanContext(config) as ctx:
            crawler = Crawler(validated_target, config, ctx)
            return await crawler.crawl()

    endpoints = asyncio.run(_run_crawl())

    table = Table(title=f"Discovered Endpoints ({len(endpoints)})", border_style="cyan")
    table.add_column("Method", style="bold yellow", width=8)
    table.add_column("Endpoint URL", style="bold white")
    table.add_column("Params / Fields", style="green")
    table.add_column("Source", style="dim cyan", width=15)

    for ep in endpoints:
        params_summary = ", ".join(ep.params.keys()) if ep.params else ""
        if ep.form_data:
            params_summary = f"[form] {', '.join(ep.form_data.keys())}"
        table.add_row(ep.method.value, ep.url, params_summary or "-", ep.source)

    console.print(table)


@app.command(name="version")
def version_cmd():
    """Display WebVuln Scanner version."""
    console.print(f"[bold cyan]WebVuln Scanner[/bold cyan] version [bold white]{__version__}[/bold white]")


if __name__ == "__main__":
    app()

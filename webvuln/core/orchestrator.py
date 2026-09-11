"""Master Scanner Orchestrator executing full scan lifecycle and report generation."""

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Type
from rich.console import Console
from rich.table import Table

from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.risk import RiskEngine
from webvuln.core.scanner import BaseScanner
from webvuln.core.target import TargetValidator
from webvuln.discovery.crawler import Crawler
from webvuln.fingerprint.technologies import TechnologyFingerprinter
from webvuln.logger import logger
from webvuln.models.finding import Finding
from webvuln.models.scan import ScanResult, ScanTarget
from webvuln.reporting.html_report import HTMLReporter
from webvuln.reporting.json_report import JSONReporter
from webvuln.scanners.api import APIScanner
from webvuln.scanners.auth import AuthScanner
from webvuln.scanners.cookies import CookieScanner
from webvuln.scanners.cors import CORSScanner
from webvuln.scanners.headers import HeaderScanner
from webvuln.scanners.idor import IDORScanner
from webvuln.scanners.redirect import OpenRedirectScanner
from webvuln.scanners.sqli import SQLiScanner
from webvuln.scanners.tls import TLSScanner
from webvuln.scanners.traversal import TraversalScanner
from webvuln.scanners.xss import XSSScanner

console = Console(force_terminal=True, legacy_windows=False)


class ScannerOrchestrator:
    """Coordinates target crawling, fingerprinting, active/passive scans, and reporting."""

    SCANNER_REGISTRY: Dict[str, Type[BaseScanner]] = {
        "headers": HeaderScanner,
        "cookies": CookieScanner,
        "cors": CORSScanner,
        "tls": TLSScanner,
        "xss": XSSScanner,
        "sqli": SQLiScanner,
        "traversal": TraversalScanner,
        "redirect": OpenRedirectScanner,
        "api": APIScanner,
        "auth": AuthScanner,
        "idor": IDORScanner,
    }

    def __init__(self, target: ScanTarget, config: ScanConfig):
        self.target = target
        self.config = config

    async def execute_scan(self) -> ScanResult:
        """Executes the full automated security assessment workflow."""
        start_time = time.monotonic()
        scan_result = ScanResult(target=self.target, start_time=datetime.now(timezone.utc))

        async with ScanContext(self.config) as context:
            # 1. Technology Fingerprinting
            logger.info(f"[*] Fingerprinting technologies on {self.target.normalized_url}...")
            scan_result.technologies = await TechnologyFingerprinter.fingerprint_target(
                self.target.normalized_url, context
            )

            # 2. Attack Surface Discovery (Crawler)
            logger.info(f"[*] Crawling attack surface...")
            crawler = Crawler(self.target, self.config, context)
            scan_result.endpoints = await crawler.crawl()

            # 3. Instantiate enabled scanner modules
            active_scanners: List[BaseScanner] = []
            for check_name in self.config.checks:
                if check_name in self.SCANNER_REGISTRY and check_name not in self.config.exclude_checks:
                    active_scanners.append(self.SCANNER_REGISTRY[check_name]())

            logger.info(f"[*] Running {len(active_scanners)} security check modules across {len(scan_result.endpoints)} endpoints...")

            # 4. Execute scanners concurrently across discovered endpoints
            raw_findings: List[Finding] = []
            for endpoint in scan_result.endpoints:
                for scanner in active_scanners:
                    try:
                        results = await scanner.scan(self.target, context, endpoint)
                        if results:
                            raw_findings.extend(results)
                    except Exception as e:
                        if self.config.verbose:
                            logger.debug(f"Scanner {scanner.name} error on {endpoint.url}: {e}")

            # 5. Finding Correlation, Risk Scoring & Deduplication
            scan_result.findings = RiskEngine.correlate_and_deduplicate(raw_findings)
            duration = round(time.monotonic() - start_time, 2)
            scan_result.calculate_summary(duration=duration)
            scan_result.summary.total_requests = context.total_requests
            scan_result.summary.overall_risk_score = RiskEngine.calculate_overall_risk(scan_result.findings)
            scan_result.end_time = datetime.now(timezone.utc)

            # 6. Generate JSON and HTML Reports
            self.config.output_dir.mkdir(parents=True, exist_ok=True)
            json_path = self.config.output_dir / "scan.json"
            html_path = self.config.output_dir / "scan.html"

            JSONReporter.generate(scan_result, json_path)
            HTMLReporter.generate(scan_result, html_path)

            logger.info(f"[+] Scan completed in {duration}s. Reports written to {self.config.output_dir}/")
            return scan_result

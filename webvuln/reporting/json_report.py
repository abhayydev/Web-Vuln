"""JSON report generator exporting structured scan findings and metadata."""

import json
from pathlib import Path
from webvuln.models.scan import ScanResult


class JSONReporter:
    """Generates machine-readable JSON security assessment reports."""

    @classmethod
    def generate(cls, scan_result: ScanResult, output_path: Path) -> Path:
        """Serializes scan results and findings into structured JSON format."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "target": scan_result.target.model_dump(),
            "start_time": scan_result.start_time.isoformat() if scan_result.start_time else None,
            "end_time": scan_result.end_time.isoformat() if scan_result.end_time else None,
            "technologies": scan_result.technologies,
            "summary": scan_result.summary.model_dump(),
            "endpoints_count": len(scan_result.endpoints),
            "findings": [f.to_dict() for f in scan_result.findings],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return output_path

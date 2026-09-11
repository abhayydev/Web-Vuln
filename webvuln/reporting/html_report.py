"""HTML report generator utilizing Jinja2 template rendering."""

from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from webvuln.models.scan import ScanResult


class HTMLReporter:
    """Renders interactive HTML reports from scan results."""

    @classmethod
    def generate(cls, scan_result: ScanResult, output_path: Path) -> Path:
        """Renders the HTML report from the Jinja2 template."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        template_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
        template = env.get_template("report.html.j2")

        rendered_html = template.render(
            target=scan_result.target,
            summary=scan_result.summary,
            technologies=scan_result.technologies,
            endpoints=scan_result.endpoints,
            findings=scan_result.findings,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        return output_path

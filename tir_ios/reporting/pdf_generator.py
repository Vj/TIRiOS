from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from tir_ios.core.models import ScanReport


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


class PDFReportGenerator:
    def __init__(self, template_dir: Path | None = None):
        tpl_dir = template_dir or (Path(__file__).resolve().parent / "templates")
        self.env = Environment(
            loader=FileSystemLoader(str(tpl_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def render_html(self, report: ScanReport) -> str:
        payload: Dict[str, Any] = json.loads(report.to_json())
        findings: List[Dict[str, Any]] = sorted(
            payload.get("findings", []),
            key=lambda item: (SEVERITY_ORDER.get(item.get("severity", "Info"), 99), -float(item.get("cvss_score", 0.0))),
        )

        severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
        for item in findings:
            sev = item.get("severity", "Info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        template = self.env.get_template("report.html.j2")
        return template.render(
            metadata=payload["metadata"],
            findings=findings,
            severity_counts=severity_counts,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

    def generate_pdf(self, report: ScanReport, output_pdf_path: Path) -> Path:
        out_path = Path(output_pdf_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        html_content = self.render_html(report)
        HTML(string=html_content).write_pdf(str(out_path))
        return out_path

    def generate_html(self, report: ScanReport, output_html_path: Path) -> Path:
        out_path = Path(output_html_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        html_content = self.render_html(report)
        out_path.write_text(html_content, encoding="utf-8")
        return out_path
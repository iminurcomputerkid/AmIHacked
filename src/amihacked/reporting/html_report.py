from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from amihacked.core.models import Finding
from amihacked.detection.scoring import RiskScore


def build_html_report(
    case_id: str,
    findings: list[Finding],
    risk_score: RiskScore,
    evidence_index: dict | None = None,
) -> str:
    template_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")
    return template.render(case_id=case_id, findings=findings, risk_score=risk_score, evidence_index=evidence_index or {})

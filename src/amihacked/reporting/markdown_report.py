from amihacked.core.models import Finding
from amihacked.detection.scoring import RiskScore


def build_markdown_report(
    case_id: str,
    findings: list[Finding],
    risk_score: RiskScore,
    evidence_index: dict | None = None,
    report_context: dict | None = None,
) -> str:
    evidence_index = evidence_index or {}
    report_context = report_context or {}
    summary = report_context.get("summary", {})
    collection_health = report_context.get("collection_health", {})
    timeline = report_context.get("timeline", [])
    lines = [
        f"# AmIHacked Report: {case_id}",
        "",
        f"Risk Score: {risk_score.score}/100 ({risk_score.level})",
        "",
        "AmIHacked does not conclude that this host is definitely compromised. It reports observed behaviors that may warrant investigation.",
        "",
        "## Executive Summary",
        "",
        f"- Findings: {summary.get('finding_count', len(findings))}",
        f"- Severity Counts: {summary.get('severity_counts', {})}",
        f"- Artifact Counts: {summary.get('artifact_counts', {})}",
        f"- Elevated Collection: {collection_health.get('elevated')}",
        "",
        "## Collection Health",
        "",
        f"- Collectors: {collection_health.get('collector_count', 0)}",
        f"- Status Counts: {collection_health.get('status_counts', {})}",
        "",
    ]
    for collector in collection_health.get("collectors", [])[:20]:
        lines.append(
            f"- {collector['name']}: {collector['status']} ({collector['artifact_count']} artifacts)"
        )
    lines.extend(
        [
            "",
            "## Top Timeline Events",
            "",
        ]
    )
    if timeline:
        for event in timeline[:25]:
            lines.append(f"- {event['timestamp']} {event['event_type']}: {event['summary']}")
    else:
        lines.append("- No timestamped events available.")
    lines.extend(
        [
            "",
            "## Findings",
            "",
        ]
    )

    if not findings:
        lines.extend(["No suspicious findings were produced by the currently enabled rules.", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- Severity: {finding.severity}",
                f"- Confidence: {finding.confidence:.2f}",
                f"- Evidence: {', '.join(finding.evidence_refs) or 'None'}",
                f"- Reason: {finding.reason}",
                f"- Score Impact: {finding.score_impact}",
                f"- Recommendation: {finding.recommendation or 'Review supporting evidence.'}",
                "",
            ]
        )
        if finding.score_details:
            lines.extend(["Score details:", ""])
            for detail in finding.score_details:
                lines.append(f"- {detail}")
            lines.append("")
        evidence_summaries = [
            evidence_index[ref]["summary"]
            for ref in finding.evidence_refs
            if ref in evidence_index and evidence_index[ref].get("summary")
        ]
        if evidence_summaries:
            lines.extend(["Evidence summaries:", ""])
            for summary in evidence_summaries[:8]:
                lines.append(f"- {summary}")
            lines.append("")

    lines.extend(["## Score Reasons", ""])
    for reason in risk_score.reasons:
        sign = "+" if reason.points >= 0 else ""
        lines.append(f"- {sign}{reason.points} {reason.reason}")
    lines.append("")
    return "\n".join(lines)

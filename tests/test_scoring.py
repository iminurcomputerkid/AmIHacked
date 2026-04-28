from amihacked.core.models import Finding
from amihacked.detection.scoring import ScoringEngine


def test_scoring_is_deterministic_and_capped():
    findings = [
        Finding(
            id="finding-0001",
            title="Encoded PowerShell",
            severity="critical",
            confidence=0.9,
            description="Suspicious behavior.",
            evidence_type="process",
            evidence_refs=["process:1", "network:1:1.1.1.1:443"],
            matched_rule="AH-TEST",
            reason="Matched test evidence.",
            recommendation="Investigate.",
            mitre_techniques=[],
        )
    ]
    evidence = {
        "process": [{"artifact_id": "process:1", "type": "process", "exe_path": "C:\\Users\\a\\AppData\\x.exe"}],
        "network": [{"artifact_id": "network:1:1.1.1.1:443", "type": "network", "is_public_remote": True}],
    }

    score = ScoringEngine().score(findings, evidence)

    assert score.score == 55
    assert score.level == "High"
    assert "+35 Critical finding" in findings[0].score_details
    assert "+10 External network connection" in findings[0].score_details


def test_duplicate_findings_are_suppressed_for_scoring():
    findings = [
        Finding(
            id="finding-a",
            title="Same Rule",
            severity="high",
            confidence=0.9,
            description="Suspicious behavior.",
            evidence_type="process",
            evidence_refs=["process:1"],
            matched_rule="AH-TEST",
            reason="Matched test evidence.",
            recommendation="Investigate.",
            mitre_techniques=[],
        ),
        Finding(
            id="finding-b",
            title="Same Rule",
            severity="high",
            confidence=0.9,
            description="Suspicious behavior.",
            evidence_type="process",
            evidence_refs=["process:1"],
            matched_rule="AH-TEST",
            reason="Matched test evidence.",
            recommendation="Investigate.",
            mitre_techniques=[],
        ),
    ]

    score = ScoringEngine().score(findings, {"process": [{"artifact_id": "process:1", "type": "process"}]})

    assert score.score == 25
    assert findings[1].score_impact == 0
    assert "Duplicate finding suppressed for scoring" in findings[1].modifiers

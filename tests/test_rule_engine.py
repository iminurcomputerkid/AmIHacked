from amihacked.detection.engine import DetectionEngine
from amihacked.detection.rule_models import DetectionRule


def test_encoded_powershell_rule_matches():
    rule = DetectionRule(
        id="AH-TEST-0001",
        name="Encoded PowerShell",
        enabled=True,
        source="process",
        severity="high",
        confidence=0.9,
        description="Detects encoded PowerShell commands.",
        conditions={
            "all": [
                {"field": "name", "equals_any": ["powershell.exe", "pwsh.exe"]},
                {"field": "command_line", "contains_any": ["-enc", "-encodedcommand"]},
            ]
        },
        recommendation="Decode the command line.",
    )

    matches, findings = DetectionEngine([rule]).run(
        {
            "process": [
                {
                    "artifact_id": "process:123",
                    "pid": 123,
                    "name": "powershell.exe",
                    "command_line": "powershell.exe -NoP -Enc AAAA",
                }
            ]
        }
    )

    assert len(matches) == 1
    assert len(findings) == 1
    assert findings[0].matched_rule == "AH-TEST-0001"
    assert findings[0].id.startswith("finding-")

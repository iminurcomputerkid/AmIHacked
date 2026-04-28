from amihacked.detection.correlation import CorrelationEngine


def test_clustered_failed_auth_logs_create_correlation():
    logs = [
        {
            "artifact_id": f"log:failed:{index}",
            "type": "log",
            "source": "systemd_journal",
            "event_id": None,
            "message": f"Failed password for invalid user admin from 192.0.2.{index}",
        }
        for index in range(5)
    ]

    findings = CorrelationEngine().run({"process": [], "network": [], "log": logs}, [])

    assert any(finding.title == "Clustered Failed Authentication Events" for finding in findings)


def test_defender_log_event_creates_high_correlation():
    logs = [
        {
            "artifact_id": "log:defender:1",
            "type": "log",
            "source": "windows_event_log",
            "provider": "Microsoft-Windows-Windows Defender",
            "event_id": 1116,
            "message": "Malware detected.",
        }
    ]

    findings = CorrelationEngine().run({"process": [], "network": [], "log": logs}, [])

    assert findings[0].title == "Security Product Detection Event Observed"
    assert findings[0].severity == "high"


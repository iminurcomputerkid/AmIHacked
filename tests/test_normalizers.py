from amihacked.normalizers.evidence import normalize_scan_evidence


def test_normalized_evidence_preserves_sources_and_deduplicates_ids():
    evidence = normalize_scan_evidence(
        {
            "process": [{"artifact_id": "process:1", "pid": 1, "name": "python"}],
            "network": [{"artifact_id": "network:1", "pid": 1}],
            "log": [{"artifact_id": "log:1", "source": "authentication", "message": "Failed password"}],
            "persistence": [],
        }
    )

    assert set(evidence) == {"process", "network", "log", "persistence"}
    assert evidence["process"][0]["type"] == "process"
    assert evidence["log"][0]["type"] == "log"


from amihacked.detection.evidence_index import build_evidence_index


def test_evidence_index_summarizes_artifacts_by_id():
    index = build_evidence_index(
        {
            "process": [
                {
                    "artifact_id": "process:1",
                    "type": "process",
                    "pid": 1,
                    "name": "powershell.exe",
                    "parent_name": "winword.exe",
                    "exe_path": "C:\\Windows\\System32\\powershell.exe",
                }
            ],
            "network": [],
            "log": [],
            "persistence": [],
        }
    )

    assert "process:1" in index
    assert "powershell.exe pid=1" in index["process:1"]["summary"]


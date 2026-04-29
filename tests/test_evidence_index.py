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
            "installed_software": [
                {
                    "artifact_id": "installed_software:1",
                    "type": "installed_software",
                    "name": "Acme App",
                    "version": "1.2.3",
                    "publisher": "Acme",
                }
            ],
            "security_posture": [
                {
                    "artifact_id": "security_posture:1",
                    "type": "security_posture",
                    "name": "Microsoft Defender Antivirus",
                    "status": "enabled",
                    "enabled": True,
                }
            ],
        }
    )

    assert "process:1" in index
    assert "powershell.exe pid=1" in index["process:1"]["summary"]
    assert "Acme App version=1.2.3" in index["installed_software:1"]["summary"]
    assert "Microsoft Defender Antivirus status=enabled" in index["security_posture:1"]["summary"]

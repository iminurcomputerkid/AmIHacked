from typing import Any

from amihacked.core.models import Finding
from amihacked.utils.ids import stable_id
from amihacked.utils.paths import looks_user_writable
from amihacked.utils.process_utils import OFFICE_PROCESS_NAMES, SHELL_PROCESS_NAMES, has_remote_url


class CorrelationEngine:
    def run(self, evidence: dict[str, list[dict[str, Any]]], existing_findings: list[Finding]) -> list[Finding]:
        findings: list[Finding] = []
        processes = evidence.get("process", [])
        networks = evidence.get("network", [])
        logs = evidence.get("log", [])
        by_pid = {process.get("pid"): process for process in processes if process.get("pid") is not None}
        public_network_by_pid: dict[int, list[dict[str, Any]]] = {}

        for connection in networks:
            if connection.get("pid") is None or connection.get("is_public_remote") is not True:
                continue
            public_network_by_pid.setdefault(connection["pid"], []).append(connection)

        for pid, process in by_pid.items():
            public_connections = public_network_by_pid.get(pid, [])
            if not public_connections:
                continue

            exe_path = process.get("exe_path")
            command_line = process.get("command_line")
            process_name = (process.get("name") or "").lower()
            parent_name = (process.get("parent_name") or "").lower()

            if looks_user_writable(exe_path):
                findings.append(
                    self._finding(
                        title="Process From User-Writable Path With External Network Connection",
                        severity="high",
                        confidence=0.8,
                        description="A process running from AppData, Temp, or another user-writable path also has an external network connection.",
                        evidence_refs=[process["artifact_id"], public_connections[0]["artifact_id"]],
                        reason=f"Process {process_name or pid} ran from {exe_path!r} and connected externally.",
                        recommendation="Inspect the executable hash, parent process, persistence entries, and remote destination.",
                        mitre=["T1105", "T1204"],
                        correlation_id="user-writable-external-network",
                    )
                )

            if parent_name in OFFICE_PROCESS_NAMES and process_name in SHELL_PROCESS_NAMES:
                findings.append(
                    self._finding(
                        title="Office Spawned Shell With External Network Connection",
                        severity="critical",
                        confidence=0.9,
                        description="An Office process spawned a shell or scripting process that has an external network connection.",
                        evidence_refs=[process["artifact_id"], public_connections[0]["artifact_id"]],
                        reason=f"{parent_name} spawned {process_name}, and that child process connected externally.",
                        recommendation="Review the document or email involved, decode command lines, and examine related network activity.",
                        mitre=["T1204", "T1059"],
                        correlation_id="office-shell-external-network",
                    )
                )

            if process_name in {"powershell.exe", "pwsh.exe"} and command_line:
                lowered = command_line.lower()
                if "-enc" in lowered or "-encodedcommand" in lowered:
                    findings.append(
                        self._finding(
                            title="Encoded PowerShell With External Network Connection",
                            severity="critical",
                            confidence=0.9,
                            description="PowerShell used encoded command arguments and has an external network connection.",
                            evidence_refs=[process["artifact_id"], public_connections[0]["artifact_id"]],
                            reason="Encoded PowerShell activity and external network activity occurred in the same process.",
                            recommendation="Decode the command, inspect the parent process, and review the destination IP/domain.",
                            mitre=["T1059.001", "T1105"],
                            correlation_id="encoded-powershell-external-network",
                        )
                    )

            if has_remote_url(command_line) and process_name.endswith(".exe"):
                findings.append(
                    self._finding(
                        title="Command Line Contains Remote URL With External Network Connection",
                        severity="high",
                        confidence=0.75,
                        description="A process command line references a remote URL and the same process has external network activity.",
                        evidence_refs=[process["artifact_id"], public_connections[0]["artifact_id"]],
                        reason=f"Command line for {process_name} referenced a URL and the process connected externally.",
                        recommendation="Review the remote URL, downloaded content, and parent process.",
                        mitre=["T1105"],
                        correlation_id="remote-url-external-network",
                    )
                )

        findings.extend(self._correlate_logs(logs, len(existing_findings) + len(findings)))
        return _dedupe_findings(findings)

    def _correlate_logs(self, logs: list[dict[str, Any]], _offset: int) -> list[Finding]:
        findings: list[Finding] = []
        failed_auth = [event for event in logs if _is_failed_auth_event(event)]
        if len(failed_auth) >= 5:
            refs = [event["artifact_id"] for event in failed_auth[:10] if event.get("artifact_id")]
            findings.append(
                self._finding(
                    title="Clustered Failed Authentication Events",
                    severity="medium",
                    confidence=0.7,
                    description="Multiple failed authentication events were observed in collected logs.",
                    evidence_refs=refs,
                    reason=f"{len(failed_auth)} failed authentication log events were observed in the collected log window.",
                    recommendation="Review source accounts, source hosts, timing, and whether failures precede a successful privileged login.",
                    mitre=["T1110"],
                    correlation_id="clustered-failed-auth",
                )
            )

        privileged_events = [event for event in logs if _is_privileged_logon_event(event)]
        if privileged_events:
            refs = [event["artifact_id"] for event in privileged_events[:5] if event.get("artifact_id")]
            findings.append(
                self._finding(
                    title="Privileged Authentication Activity Observed",
                    severity="low",
                    confidence=0.55,
                    description="Logs show privileged authentication or special privilege assignment activity.",
                    evidence_refs=refs,
                    reason=f"{len(privileged_events)} privileged authentication-related events were present.",
                    recommendation="Confirm the privileged activity matches expected administrator behavior for the time window.",
                    mitre=["T1078"],
                    correlation_id="privileged-auth-activity",
                )
            )

        service_or_task_events = [event for event in logs if _is_service_or_task_creation_event(event)]
        if service_or_task_events:
            refs = [event["artifact_id"] for event in service_or_task_events[:5] if event.get("artifact_id")]
            findings.append(
                self._finding(
                    title="Service Or Scheduled Task Creation Observed In Logs",
                    severity="medium",
                    confidence=0.72,
                    description="Logs show service installation or scheduled task creation events.",
                    evidence_refs=refs,
                    reason=f"{len(service_or_task_events)} service/task creation events were observed in logs.",
                    recommendation="Review service/task names, commands, authors, and whether they point to user-writable paths.",
                    mitre=["T1053", "T1543"],
                    correlation_id="service-task-creation-logs",
                )
            )

        defender_events = [event for event in logs if _is_defender_detection_event(event)]
        if defender_events:
            refs = [event["artifact_id"] for event in defender_events[:5] if event.get("artifact_id")]
            findings.append(
                self._finding(
                    title="Security Product Detection Event Observed",
                    severity="high",
                    confidence=0.85,
                    description="Collected logs include malware or security product detection events.",
                    evidence_refs=refs,
                    reason=f"{len(defender_events)} security detection events were observed in logs.",
                    recommendation="Review the detection name, affected path, remediation status, and surrounding process activity.",
                    mitre=["TA0005"],
                    correlation_id="security-product-detection",
                )
            )

        return findings

    @staticmethod
    def _finding(
        title: str,
        severity: str,
        confidence: float,
        description: str,
        evidence_refs: list[str],
        reason: str,
        recommendation: str,
        mitre: list[str],
        correlation_id: str,
    ) -> Finding:
        return Finding(
            id=stable_id("finding", correlation_id, *sorted(evidence_refs)),
            title=title,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence_type="correlation",
            evidence_id=None,
            evidence_refs=evidence_refs,
            matched_rule=None,
            reason=reason,
            recommendation=recommendation,
            mitre_techniques=mitre,
        )


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        unique.append(finding)
    return unique


def _event_id(event: dict[str, Any]) -> str:
    return str(event.get("event_id") or "").strip()


def _message(event: dict[str, Any]) -> str:
    return str(event.get("message") or "").lower()


def _is_failed_auth_event(event: dict[str, Any]) -> bool:
    event_id = _event_id(event)
    message = _message(event)
    return event_id in {"4625"} or any(token in message for token in ("failed password", "authentication failure", "failed login"))


def _is_privileged_logon_event(event: dict[str, Any]) -> bool:
    event_id = _event_id(event)
    message = _message(event)
    return event_id in {"4672", "4648"} or "session opened for user root" in message or "sudo" in message and "command=" in message


def _is_service_or_task_creation_event(event: dict[str, Any]) -> bool:
    event_id = _event_id(event)
    message = _message(event)
    return event_id in {"4697", "4698", "7045"} or "created task" in message or "service installed" in message


def _is_defender_detection_event(event: dict[str, Any]) -> bool:
    event_id = _event_id(event)
    source = str(event.get("source") or "").lower()
    provider = str(event.get("provider") or "").lower()
    message = _message(event)
    return (
        event_id in {"1116", "1117"}
        or "defender" in provider
        and ("detected" in message or "malware" in message)
        or "security product" in source
        and "detected" in message
    )

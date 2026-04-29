from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from amihacked.config import AppConfig
from amihacked.constants import DEFAULT_CASES_DIR, PENDING_RULES_DIR
from amihacked.collectors.common.logs import LogCollector
from amihacked.collectors.common.network import NetworkCollector
from amihacked.collectors.common.processes import ProcessCollector
from amihacked.collectors.common.system import SystemCollector
from amihacked.collectors.linux.linux_persistence import LinuxPersistenceCollector
from amihacked.collectors.linux.linux_services import LinuxServicesCollector
from amihacked.collectors.macos.macos_persistence import MacOSPersistenceCollector
from amihacked.collectors.windows.windows_installed_software import WindowsInstalledSoftwareCollector
from amihacked.collectors.windows.windows_registry import WindowsRegistryCollector
from amihacked.collectors.windows.windows_scheduled_tasks import WindowsScheduledTasksCollector
from amihacked.collectors.windows.windows_security_posture import WindowsSecurityPostureCollector
from amihacked.collectors.windows.windows_services import WindowsServicesCollector
from amihacked.collectors.windows.windows_startup_items import WindowsStartupItemsCollector
from amihacked.core.permissions import elevation_status, is_elevated, relaunch_with_elevation
from amihacked.core.platform_detect import current_platform
from amihacked.core.scan_context import ScanContext
from amihacked.detection.correlation import CorrelationEngine
from amihacked.detection.engine import DetectionEngine
from amihacked.detection.evidence_index import build_evidence_index
from amihacked.detection.rule_describer import describe_rule_conditions
from amihacked.detection.rule_loader import RuleLoader, validate_rule
from amihacked.detection.scoring import ScoringEngine
from amihacked.normalizers.evidence import normalize_scan_evidence
from amihacked.reporting.html_report import build_html_report
from amihacked.reporting.context import build_collection_health, build_report_context, sort_findings
from amihacked.reporting.json_report import build_json_report
from amihacked.reporting.markdown_report import build_markdown_report
from amihacked.reporting.timeline import build_timeline
from amihacked.storage.case_reader import CaseReader
from amihacked.storage.case_writer import CaseWriter
from amihacked.utils.runtime import ScanRuntime, format_duration
from amihacked.utils.time import timestamp_for_id


app = typer.Typer(help="Local endpoint triage and evidence collection.")
console = Console()


@app.command()
def scan(
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Case output directory.")] = None,
    full: Annotated[bool, typer.Option("--full", help="Run full scan collectors when available.")] = False,
    skip_logs: Annotated[bool, typer.Option("--skip-logs", help="Skip local log/event collection.")] = False,
    log_lines: Annotated[int, typer.Option("--log-lines", min=100, help="Maximum file log lines to collect per log source.")] = 5000,
    allow_unelevated: Annotated[
        bool,
        typer.Option(
            "--allow-unelevated",
            help="Permit a best-effort scan without admin/root. Some process, network, and log artifacts may be missing.",
        ),
    ] = False,
    no_auto_elevate: Annotated[
        bool,
        typer.Option("--no-auto-elevate", help="Do not attempt sudo/UAC relaunch when scan is not elevated."),
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show more command output.")] = False,
) -> None:
    """Collect endpoint evidence, run enabled rules, and write reports."""
    runtime = ScanRuntime()
    started_at = runtime.started_at
    privilege = elevation_status()
    if not privilege.elevated and not allow_unelevated:
        if not no_auto_elevate and relaunch_with_elevation():
            console.print("[yellow]Elevation requested. Continue in the elevated AmIHacked window.[/yellow]")
            raise typer.Exit(0)
        console.print("[bold red]AmIHacked scan requires elevated privileges.[/bold red]")
        console.print(f"Required account level: [bold]{privilege.required_account}[/bold]")
        console.print(privilege.guidance)
        raise typer.Exit(2)
    if not privilege.elevated and allow_unelevated:
        console.print(
            "[bold yellow]Running unelevated by explicit request.[/bold yellow] "
            "Collection may miss protected processes, owning PIDs, and security logs."
        )

    case_id = output.name if output else f"case-{timestamp_for_id()}"
    case_dir = output or DEFAULT_CASES_DIR / case_id
    config = AppConfig(include_full_collectors=full)
    context = ScanContext(
        case_id=case_id,
        case_dir=case_dir,
        started_at=started_at,
        platform=current_platform(),
        mode="full" if full else "basic",
        elevated=is_elevated(),
    )
    writer = CaseWriter(case_dir=case_dir, case_id=case_id, collected_at=started_at)
    writer.initialize()

    console.print(
        f"[bold]AmIHacked scan[/bold] case={case_id} platform={context.platform} "
        f"mode={context.mode} elevated={context.elevated}"
    )

    collectors = [SystemCollector(), ProcessCollector(), NetworkCollector()]
    if context.platform == "windows":
        collectors.extend(
            [
                WindowsStartupItemsCollector(),
                WindowsRegistryCollector(),
                WindowsScheduledTasksCollector(),
                WindowsServicesCollector(),
                WindowsInstalledSoftwareCollector(),
                WindowsSecurityPostureCollector(),
            ]
        )
    elif context.platform == "linux":
        collectors.extend([LinuxServicesCollector(), LinuxPersistenceCollector()])
    elif context.platform == "macos":
        collectors.append(MacOSPersistenceCollector())
    if not skip_logs:
        collectors.append(LogCollector(max_lines_per_file=log_lines))
    collector_results = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("Preparing scan", total=None)
        for collector in collectors:
            progress.update(task_id, description=f"Collecting {collector.name}")
            with runtime.stage(f"collect:{collector.name}") as timing:
                result = collector.collect(context)
                timing.artifacts = len(result.artifacts)
            collector_results[collector.name] = result
            status_style = "green" if result.status == "ok" else "yellow"
            console.print(f"Collected [{status_style}]{collector.name}[/{status_style}]: {len(result.artifacts)} artifacts")
            if verbose:
                for warning in result.warnings:
                    console.print(f"[yellow]warning[/yellow] {warning}")
                for error in result.errors:
                    console.print(f"[red]error[/red] {error}")
        progress.update(task_id, description="Collection complete")

    system_result = collector_results["system"]
    processes_result = collector_results["processes"]
    network_result = collector_results["network_connections"]
    log_result = collector_results.get("log_events")
    startup_result = collector_results.get("startup_items")
    registry_result = collector_results.get("registry_run_keys")
    scheduled_tasks_result = collector_results.get("scheduled_tasks")
    services_result = collector_results.get("services")
    installed_software_result = collector_results.get("installed_software")
    security_posture_result = collector_results.get("security_posture")
    platform_persistence_result = collector_results.get("platform_persistence")
    persistence_artifacts = [
        *(startup_result.artifacts if startup_result else []),
        *(registry_result.artifacts if registry_result else []),
        *(scheduled_tasks_result.artifacts if scheduled_tasks_result else []),
        *(services_result.artifacts if services_result else []),
        *(platform_persistence_result.artifacts if platform_persistence_result else []),
    ]

    with runtime.stage("write:raw_artifacts"):
        writer.write_json("raw/system_info.json", system_result.artifacts[0] if system_result.artifacts else {}, "system")
        writer.write_json("raw/processes.json", processes_result.artifacts, "process")
        writer.write_json("raw/network_connections.json", network_result.artifacts, "network")
        writer.write_json("raw/startup_items.json", startup_result.artifacts if startup_result else [], "startup_items")
        writer.write_json("raw/registry_run_keys.json", registry_result.artifacts if registry_result else [], "registry_run_keys")
        writer.write_json("raw/scheduled_tasks.json", scheduled_tasks_result.artifacts if scheduled_tasks_result else [], "scheduled_tasks")
        writer.write_json("raw/services.json", services_result.artifacts if services_result else [], "services")
        writer.write_json(
            "raw/platform_persistence.json",
            platform_persistence_result.artifacts if platform_persistence_result else [],
            "platform_persistence",
        )
        writer.write_json(
            "raw/installed_software.json",
            installed_software_result.artifacts if installed_software_result else [],
            "installed_software",
        )
        writer.write_json(
            "raw/security_posture.json",
            security_posture_result.artifacts if security_posture_result else [],
            "security_posture",
        )
        writer.write_json("raw/log_events.json", log_result.artifacts if log_result else [], "log")
        writer.write_json(
            "raw/process_network_map.json",
            _build_process_network_map(processes_result.artifacts, network_result.artifacts),
            "process_network_map",
        )

    raw_evidence = {
        "process": processes_result.artifacts,
        "network": network_result.artifacts,
        "log": log_result.artifacts if log_result else [],
        "persistence": persistence_artifacts,
        "installed_software": installed_software_result.artifacts if installed_software_result else [],
        "security_posture": security_posture_result.artifacts if security_posture_result else [],
    }
    with runtime.stage("normalize:evidence") as timing:
        evidence = normalize_scan_evidence(raw_evidence)
        timing.artifacts = sum(len(items) for items in evidence.values())

    with runtime.stage("write:normalized_artifacts"):
        writer.write_json("normalized/processes.normalized.json", evidence["process"], "normalized_process")
        writer.write_json("normalized/network.normalized.json", evidence["network"], "normalized_network")
        writer.write_json("normalized/logs.normalized.json", evidence["log"], "normalized_log")
        writer.write_json("normalized/persistence.normalized.json", evidence["persistence"], "normalized_persistence")
        writer.write_json(
            "normalized/installed_software.normalized.json",
            evidence["installed_software"],
            "normalized_installed_software",
        )
        writer.write_json(
            "normalized/security_posture.normalized.json",
            evidence["security_posture"],
            "normalized_security_posture",
        )

    with runtime.stage("detect:rules") as timing:
        rules, validation_results = RuleLoader(config.rule_dirs).load_rules()
        matches, findings = DetectionEngine(rules).run(evidence)
        timing.artifacts = len(matches)
        timing.notes = f"{len(rules)} enabled rules loaded"

    with runtime.stage("detect:correlations") as timing:
        correlations = CorrelationEngine().run(evidence, findings)
        findings.extend(correlations)
        timing.artifacts = len(correlations)

    with runtime.stage("score:findings") as timing:
        risk_score = ScoringEngine().score(findings, evidence)
        timing.artifacts = len(findings)

    with runtime.stage("write:findings_reports"):
        metadata = _metadata(context, runtime)
        evidence_index = build_evidence_index(evidence)
        timeline = build_timeline(evidence, findings)
        report_context = build_report_context(metadata, findings, evidence, collector_results, timeline)
        sorted_findings = sort_findings(findings)
        writer.write_json("findings/rule_matches.json", matches, "rule_matches")
        writer.write_json("findings/correlations.json", correlations, "correlations")
        writer.write_json("findings/findings.json", sorted_findings, "findings")
        writer.write_json("findings/risk_score.json", risk_score, "risk_score")
        writer.write_json("findings/rule_validation.json", validation_results, "rule_validation")
        writer.write_json("findings/evidence_index.json", evidence_index, "evidence_index")
        writer.write_json("findings/timeline.json", timeline, "timeline")
        writer.write_json("findings/collection_health.json", report_context["collection_health"], "collection_health")
        writer.write_json("findings/finding_groups.json", report_context["finding_groups"], "finding_groups")

        writer.write_json("reports/report.json", build_json_report(case_id, sorted_findings, risk_score, evidence_index, report_context), "report")
        writer.write_text("reports/report.md", build_markdown_report(case_id, sorted_findings, risk_score, evidence_index, report_context), "report")
        writer.write_text("reports/report.html", build_html_report(case_id, sorted_findings, risk_score, evidence_index, report_context), "report")

    writer.write_json("metadata.json", _metadata(context, runtime), "metadata")
    writer.write_manifest()

    console.print(f"[bold green]Scan complete[/bold green] {case_dir}")
    console.print(f"Elapsed: [bold]{format_duration(runtime.elapsed_seconds())}[/bold]")
    console.print(f"Risk Score: [bold]{risk_score.score}/100[/bold] ({risk_score.level})")
    console.print(f"Findings: [bold]{len(findings)}[/bold]")


@app.command("update-intel")
def update_intel(
    source: Annotated[str | None, typer.Option("--source", help="Intel source to update.")] = None,
) -> None:
    """Placeholder for data/rule updates. Python code is never auto-updated."""
    selected = source or "all"
    console.print(f"Intel update plumbing is reserved for v0.5. Requested source: {selected}")


@app.command("validate-rules")
def validate_rules() -> None:
    """Validate enabled builtin/community rules without running a scan."""
    rules, validation_results = RuleLoader(AppConfig().rule_dirs, include_disabled=True).load_rules()
    valid_count = sum(1 for result in validation_results if result.valid)
    invalid = [result for result in validation_results if not result.valid]
    warning_count = sum(len(result.warnings) for result in validation_results)

    table = Table(title="Rule Validation")
    table.add_column("Rule ID")
    table.add_column("Valid")
    table.add_column("Errors")
    table.add_column("Warnings")
    for result in validation_results:
        table.add_row(
            result.rule_id or "<unknown>",
            str(result.valid),
            "; ".join(result.errors),
            "; ".join(result.warnings),
        )
    console.print(table)
    console.print(f"Rules loaded: {len(rules)} | Valid: {valid_count} | Invalid: {len(invalid)} | Warnings: {warning_count}")
    if invalid:
        raise typer.Exit(1)


@app.command("review-rules")
def review_rules() -> None:
    """List pending rules and validation status."""
    pending_files = (
        sorted(PENDING_RULES_DIR.rglob("*.yml"))
        + sorted(PENDING_RULES_DIR.rglob("*.yaml"))
        + sorted(PENDING_RULES_DIR.rglob("*.json"))
    )
    if not pending_files:
        console.print("No pending rules found.")
        return

    rules, validation_results = RuleLoader([PENDING_RULES_DIR], include_disabled=True).load_rules()
    table = Table(title="Pending Rules")
    table.add_column("Rule ID")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Valid")
    table.add_column("Logic")
    result_by_id = {result.rule_id: result for result in validation_results}
    rendered_ids: set[str | None] = set()
    for rule in rules:
        result = result_by_id.get(rule.id)
        rendered_ids.add(rule.id)
        table.add_row(
            rule.id,
            rule.name,
            rule.severity,
            f"{rule.confidence:.2f}",
            str(result.valid if result else False),
            describe_rule_conditions(rule.conditions),
        )
    for result in validation_results:
        if result.rule_id in rendered_ids or result.valid:
            continue
        table.add_row(
            result.rule_id or "<unknown>",
            "<invalid rule>",
            "-",
            "-",
            "False",
            "; ".join(result.errors),
        )
    console.print(table)


@app.command()
def report(case_dir: Annotated[Path, typer.Argument(help="Existing case directory.")]) -> None:
    """Rebuild reports for an existing case from saved findings and normalized evidence."""
    reader = CaseReader(case_dir)
    metadata = reader.read_json("metadata.json", {})
    case_id = metadata.get("case_id") or case_dir.name
    findings = sort_findings(reader.read_findings())
    risk_score = reader.read_risk_score()
    evidence = reader.read_evidence()
    evidence_index = reader.read_json("findings/evidence_index.json", None) or build_evidence_index(evidence)
    timeline = reader.read_json("findings/timeline.json", None) or build_timeline(evidence, findings)
    collection_health = reader.read_json("findings/collection_health.json", None)
    report_context = build_report_context(metadata, findings, evidence, None, timeline)
    if collection_health:
        report_context["collection_health"] = collection_health

    writer = CaseWriter(case_dir=case_dir, case_id=case_id, collected_at=metadata.get("created_at") or timestamp_for_id())
    writer.initialize()
    writer.write_json("findings/evidence_index.json", evidence_index, "evidence_index")
    writer.write_json("findings/timeline.json", timeline, "timeline")
    writer.write_json("findings/collection_health.json", report_context["collection_health"], "collection_health")
    writer.write_json("findings/finding_groups.json", report_context["finding_groups"], "finding_groups")
    writer.write_json("reports/report.json", build_json_report(case_id, findings, risk_score, evidence_index, report_context), "report")
    writer.write_text("reports/report.md", build_markdown_report(case_id, findings, risk_score, evidence_index, report_context), "report")
    writer.write_text("reports/report.html", build_html_report(case_id, findings, risk_score, evidence_index, report_context), "report")
    console.print(f"[bold green]Reports rebuilt[/bold green] {case_dir / 'reports'}")


@app.command()
def ask(case_dir: Annotated[Path, typer.Argument(help="Existing case directory.")], question: str) -> None:
    """Reserved for later LLM-assisted finding explanation."""
    console.print("LLM-assisted case questions are planned for v0.6.")
    console.print(f"Case: {case_dir}")
    console.print(f"Question: {question}")


def _metadata(context: ScanContext, runtime: ScanRuntime) -> dict:
    return {
        "case_id": context.case_id,
        "created_at": context.started_at,
        "platform": context.platform,
        "mode": context.mode,
        "elevated": context.elevated,
        "privilege_warning": None
        if context.elevated
        else "Scan was explicitly allowed to run unelevated. Some protected artifacts may be missing.",
        "scanner": "amihacked",
        "runtime": runtime.as_dict(),
    }


def _build_process_network_map(processes: list[dict], connections: list[dict]) -> list[dict]:
    by_pid = {process.get("pid"): process for process in processes if process.get("pid") is not None}
    rows: list[dict] = []
    for connection in connections:
        process = by_pid.get(connection.get("pid"))
        rows.append(
            {
                "artifact_id": f"process_network:{connection.get('artifact_id')}",
                "pid": connection.get("pid"),
                "process_artifact_id": process.get("artifact_id") if process else None,
                "network_artifact_id": connection.get("artifact_id"),
                "process_name": process.get("name") if process else connection.get("process_name"),
                "exe_path": process.get("exe_path") if process else None,
                "command_line": process.get("command_line") if process else None,
                "local_address": connection.get("local_address"),
                "local_port": connection.get("local_port"),
                "remote_address": connection.get("remote_address"),
                "remote_port": connection.get("remote_port"),
                "status": connection.get("status"),
                "protocol": connection.get("protocol"),
                "is_public_remote": connection.get("is_public_remote"),
            }
        )
    return rows


if __name__ == "__main__":
    app()

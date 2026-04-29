# Changelog

All notable AmIHacked implementation changes are tracked here.

## Unreleased

- Next planned milestone: `v0.5` intel update system.
- Planned focus: local intel snapshots, source scaffolding for Sigma/LOLBAS/MITRE/CISA KEV, and conversion into rule candidates without modifying Python code.

## v0.4.1

- Added Windows installed software collection from HKLM/HKCU registry uninstall keys, including 32-bit WOW6432Node entries.
- Added Windows security posture collection for Defender status, firewall profiles, Security Center antivirus products, UAC settings, and Defender Tamper Protection registry state when accessible.
- Added Linux service inventory collection from systemd unit files with `systemctl` state enrichment when available.
- Added Linux persistence collection for cron entries and XDG autostart desktop entries.
- Added macOS persistence collection for LaunchAgents, LaunchDaemons, and basic cron entries.
- Added raw and normalized case outputs for installed software and security posture evidence.
- Wired Linux/macOS platform persistence artifacts into raw case output, normalized persistence evidence, correlations, scoring, timeline, and reports.
- Enriched network connection artifacts with process path, command line, username, process create time, and IPv4/IPv6 family where accessible.
- Hardened Windows service path enrichment with a PowerShell/CIM fallback for systems where WMIC is unavailable.
- Replaced the stale Windows Event Log placeholder collector with a wrapper around the working common Windows log collector.
- Added evidence index summaries and rule-validation field support for installed software, security posture, and platform persistence metadata.
- Tightened user-writable persistence matching to evaluate extracted executable paths instead of benign `/tmp` command arguments.
- Added mocked tests for Windows installed software/security posture, CIM service enrichment, Linux systemd services, Linux cron/XDG autostart, macOS launchd persistence, and Windows Event Log wrapping.

## v0.4.0

- Added report context generation for executive summaries, artifact counts, severity counts, and top findings.
- Added collection health summaries with collector statuses, artifact counts, warnings, errors, privilege status, and status counts.
- Added timeline generation from process start times, log timestamps, persistence modification times, and timestamped findings.
- Added finding grouping by process, persistence item, or network evidence reference.
- Sorted findings by severity and confidence before writing findings and reports.
- Added `findings/timeline.json`, `findings/collection_health.json`, and `findings/finding_groups.json`.
- Enriched JSON reports with structured report context.
- Enriched Markdown reports with executive summary, collection health, and timeline sections.
- Enriched HTML reports with executive summary metrics, collection health, timeline, and finding group sections.
- Implemented `amihacked report <case_dir>` to rebuild JSON, Markdown, and HTML reports from an existing case.
- Added case-reading helpers for report regeneration.
- Added tests for timeline generation, report context, and report regeneration.

## v0.3.0

- Added Windows Registry Run/RunOnce persistence collection for HKCU, HKLM, and HKLM WOW6432Node autorun paths.
- Added Windows Startup folder persistence collection for user and all-users startup folders.
- Added best-effort `.lnk` target resolution for Startup folder shortcuts through PowerShell COM when available.
- Added Windows scheduled task collection through `schtasks /query /fo CSV /v`.
- Added Windows service collection through `psutil.win_service_iter()` with WMIC binary path enrichment when available.
- Added raw persistence output files for startup items, registry run keys, scheduled tasks, and services.
- Added combined normalized persistence output through `normalized/persistence.normalized.json`.
- Added persistence path derivation from command lines during normalization.
- Added persistence correlations for user-writable paths, remote URLs, and living-off-the-land binaries.
- Added persistence rules for scheduled task user-writable paths, service user-writable paths, and remote URL commands.
- Expanded supported persistence fields for rule validation.
- Added Windows persistence collector tests with mocked Windows APIs/commands.
- Expanded tests to cover persistence normalization and persistence correlations.

## v0.2.0

- Added elevated scan enforcement with Administrator/root required by default.
- Added explicit `--allow-unelevated` development escape hatch.
- Added elapsed scan timing, per-stage runtime metadata, and progress display.
- Added log/event artifacts as first-class evidence.
- Added Linux `journalctl` collection with file-backed `/var/log` fallback.
- Added Windows Event Log query plumbing for Security, System, Application, PowerShell, and Defender channels.
- Added normalized evidence output for process, network, log, and persistence streams.
- Changed detections to run against normalized evidence.
- Added stronger rule validation for unsupported fields/operators, unsafe tokens, and overly broad rules.
- Added `amihacked validate-rules`.
- Added stable finding IDs.
- Added duplicate finding suppression in deterministic scoring.
- Added per-finding score details.
- Added `findings/evidence_index.json` with analyst-readable artifact summaries.
- Added evidence summaries to JSON, Markdown, and HTML reports.
- Added log rules for authentication failures, service installation, PowerShell script block events, and Defender detections.
- Added log correlations for clustered failed authentication, privileged authentication, service/task creation, and security product detections.
- Fixed project root discovery so CLI commands find repo-local `rules/` and `output/`.
- Expanded tests to cover permissions, log collection, rule validation, correlations, evidence indexing, scoring, and CLI rule validation.

## v0.1.0

- Added initial package and CLI scaffold.
- Added `amihacked scan`.
- Added case folder creation under `output/cases/`.
- Added system, process, and network collectors using `psutil`.
- Added process/network join artifact.
- Added Pydantic models for core artifacts, collector results, rule matches, and findings.
- Added YAML rule loading and initial rule validation.
- Added initial detection engine and supported operators.
- Added deterministic risk scoring.
- Added JSON, Markdown, and HTML report generation.
- Added manifest hashing for evidence/report files.
- Added builtin starter rules for encoded PowerShell, Office spawning shells, LOLBins, user-writable paths, network listeners, and persistence placeholders.

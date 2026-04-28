# AmIHacked

AmIHacked is a local endpoint triage, suspicious behavior detection, and evidence collection tool.

It does not claim that a host is definitely hacked. It records observed behavior, explains why it may be suspicious, cites supporting evidence, and suggests what an analyst should investigate next.

## Quick Start

```bash
python -m pip install -e .
sudo amihacked scan
```

By default, cases are written under `output/cases/`.

```bash
sudo amihacked scan --output ./output/cases/case001
sudo amihacked scan --full
sudo amihacked scan --skip-logs
sudo amihacked scan --log-lines 10000
amihacked validate-rules
```

On Windows, run from an elevated PowerShell or Command Prompt. `amihacked scan` requires Administrator/root privileges by default because protected process details, network ownership, authentication logs, and security logs are often hidden from normal users. Use `--allow-unelevated` only for development or intentionally incomplete best-effort scans.

## Current Version

`v0.3` provides a local snapshot scanner with persistence collection and a hardened rule pipeline:

- System information collection
- Process collection with parent process mapping and executable hashes when accessible
- Network connection collection with process ownership and public/private remote IP classification
- Local log/event collection as first-class evidence (`source: log`)
- Windows persistence collection for Registry Run/RunOnce keys, Startup folders, scheduled tasks, and services
- A process/network join artifact
- Normalized evidence files under `normalized/`
- Rule matches, correlations, risk score, rule validation results, and evidence summaries under `findings/`
- YAML-backed detections with stronger rule validation
- Deterministic risk scoring with duplicate suppression and per-finding score details
- JSON, Markdown, and HTML reports with evidence summaries
- Evidence file hashing in `manifest.json`
- Elapsed scan timing and per-stage runtime metadata
- Standalone `amihacked validate-rules` command

See `CHANGELOG.md` for the running implementation history.

## Detection Coverage

The current builtin rules and correlations cover early suspicious behaviors:

- Encoded PowerShell
- Office spawning shell or scripting processes
- Executables running from user-writable directories
- MSHTA, Regsvr32, and Certutil remote-content patterns
- Unknown external connections and unusual high-port listeners
- Failed authentication activity
- Service or scheduled task creation events in logs
- PowerShell script block logging events
- Defender malware detection events
- Registry, scheduled task, service, and Startup folder persistence evidence
- Persistence entries pointing to AppData, Temp, Users Public, or remote URLs
- Correlations for suspicious process paths plus external network activity
- Correlations for persistence using user-writable paths, remote URLs, or LOLBins
- Correlations for clustered failed auth, privileged auth activity, service/task creation, and security product detections

## Persistence Collection

On Windows, v0.3 collects:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- User and all-users Startup folders
- Scheduled tasks
- Services

These sources are normalized into `normalized/persistence.normalized.json` and participate in rule matching, correlations, scoring, and reports.

## Log Collection

Logs are collected by default because historical activity is as important as current process and network state.

- Windows: Security, System, Application, PowerShell, PowerShell Operational, and Defender event logs are queried through PowerShell when available.
- Linux: systemd journal is queried with `journalctl`, then common auth, system, audit, kernel, and package/application logs are tailed from `/var/log`.
- macOS: initial support reads common system and install logs.

Use `--skip-logs` for a faster scan, or `--log-lines` to tune how much file-backed log history is collected per source.

## Case Output Highlights

Important case files:

- `raw/`: collector output before cleanup
- `normalized/`: stable artifacts used by detections
- `findings/rule_matches.json`: direct YAML rule hits
- `findings/correlations.json`: combined-signal findings
- `findings/evidence_index.json`: artifact IDs mapped to analyst-readable evidence summaries
- `findings/risk_score.json`: deterministic score and reasons
- `reports/`: JSON, Markdown, and HTML analyst reports

## Next Milestone

`v0.4` is report and analyst workflow polish: richer HTML sections, finding grouping, case summaries, and easier evidence navigation.

## Design Boundary

- Python code handles collection, normalization, validation, scoring, reporting, and storage.
- YAML/JSON rules hold detection logic.
- Intel data lives under `intel_data/`.
- LLM-generated detections must be saved under `rules/pending/` for review before enabling.

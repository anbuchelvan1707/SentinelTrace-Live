# SentinelTrace-Live
**Local-first Windows SOC event collection, normalization, and detection lab**

SentinelTrace-Live is a defensive portfolio project for collecting Windows Sysmon events, normalizing them into JSONL, applying transparent detection rules, and generating a reviewable alert report.

## Features
- Collect recent events from `Microsoft-Windows-Sysmon/Operational` using Windows PowerShell.
- Normalize common Sysmon fields while retaining the original event payload.
- Analyze existing JSONL files without requiring administrator privileges.
- Transparent, explainable detections for suspicious process execution patterns.
- JSONL alerts and a human-readable Markdown report.
- Unit tests and sample data so the project can be explored without live Sysmon events.

## Requirements
- Windows 10/11
- Python 3.10+
- Sysmon installed and logging to `Microsoft-Windows-Sysmon/Operational` for live collection
- PowerShell available on Windows

No external Python packages are required.

## Quick start (sample data, any OS)
From this directory:

```powershell
python -m sentineltrace.cli analyze --input samples/events.jsonl --out output
```

This writes:
- `output/alerts.jsonl`
- `output/report.md`

## Live collection (Windows)
Open PowerShell in the project directory. First verify the log exists:

```powershell
wevtutil gl Microsoft-Windows-Sysmon/Operational
```

Then collect the latest 100 events:

```powershell
python -m sentineltrace.cli collect --count 100 --out data/events.jsonl
```

If access is denied, open PowerShell as Administrator or grant appropriate Event Log access. Do not disable endpoint protections to make collection work.

## Analyze your existing collector output
If you already have `events.jsonl` from your own collector:

```powershell
python -m sentineltrace.cli analyze --input C:\Users\YOUR_USER\SentinelTrace-Live\events.jsonl --out output
```

The parser accepts JSONL records with common field names such as `Image`, `ProcessName`, `CommandLine`, `ParentImage`, `EventID`, `UtcTime`, `ProcessId`, and `ParentProcessId`. It also looks inside nested `event`, `EventData`, or `data` objects. If your collector uses different names, update the aliases in `sentineltrace/normalize.py`.

## Detection rules
1. **Encoded PowerShell** — command line contains common encoded-command switches.
2. **Suspicious script host** — script-capable Windows utilities launched with notable script/remote-execution indicators.
3. **Living-off-the-land utility** — selected dual-use utilities launched with a remote URL, download, or script indicator.
4. **Unusual parent-child process** — common Office/document-reader parents spawning shells or script hosts.
5. **Executable from user-writable location** — process image is under common temporary/download/user profile locations.
6. **Credential-access utility** — known administrative credential-dumping utility names are observed.

These are triage heuristics, not proof of maliciousness. False positives are expected. Validate every alert against approved software and surrounding endpoint evidence.

## Project layout
```text
SentinelTrace-Live-Complete/
├── sentineltrace/
│   ├── cli.py
│   ├── collect.py
│   ├── detect.py
│   └── normalize.py
├── samples/events.jsonl
├── tests/test_detection.py
├── requirements.txt
└── README.md
```

## Run tests
```powershell
python -m unittest discover -s tests -v
```

## Suggested demo
1. Run the sample analysis.
2. Open `output/report.md` and explain why each alert triggered.
3. Collect a small number of local Sysmon events on your own Windows machine.
4. Analyze the collected JSONL and compare alerts to known benign activity.
5. Record precision/false-positive observations in your project report.

## Limitations
- The collector uses the Windows Event Log API through PowerShell and requires the Sysmon channel to be available.
- Rules are intentionally transparent and static; they are not a substitute for an EDR or SIEM.
- This project does not execute payloads, modify endpoint settings, or automatically remediate systems.

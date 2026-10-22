
"""Transparent, explainable defensive heuristics for normalized process events."""
from __future__ import annotations
from pathlib import PureWindowsPath
from typing import Any

SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
LOLBINS = {"certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe", "mshta.exe", "wmic.exe"}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrord64.exe"}
WRITABLE_MARKERS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\", "\\downloads\\")

def _basename(path: Any) -> str:
    if not path:
        return ""
    return str(path).replace("/", "\\").rstrip("\\").split("\\")[-1].lower()

def detect_event(event: dict[str, Any]) -> list[dict[str, str]]:
    """Return alert dictionaries; rules favor explainability over certainty."""
    alerts: list[dict[str, str]] = []
    image = str(event.get("image") or "")
    command = str(event.get("command_line") or "")
    parent = str(event.get("parent_image") or "")
    image_name, parent_name = _basename(image), _basename(parent)
    cmd = command.lower()
    image_lower = image.lower().replace("/", "\\")

    def add(rule_id: str, severity: str, title: str, reason: str) -> None:
        alerts.append({
            "rule_id": rule_id, "severity": severity, "title": title,
            "reason": reason, "image": image, "command_line": command,
            "parent_image": parent, "timestamp": str(event.get("timestamp") or ""),
            "event_id": str(event.get("event_id") or ""),
            "process_id": str(event.get("process_id") or ""),
        })

    if image_name in {"powershell.exe", "pwsh.exe"} and any(x in cmd for x in (" -enc ", " -encodedcommand ", " -e ")):
        add("STL-001", "high", "Encoded PowerShell command",
            "PowerShell command line contains an encoded-command switch; inspect the decoded content and parent process.")

    if image_name in SHELLS and any(x in cmd for x in ("http://", "https://", "downloadstring", "downloadfile", "invoke-webrequest", " -enc", " -encodedcommand")):
        add("STL-002", "medium", "Script host with remote or encoded indicator",
            "A script-capable Windows process includes a remote, download, or encoded-execution indicator.")

    if image_name in LOLBINS and any(x in cmd for x in ("http://", "https://", "download", "javascript:", "vbscript:", "/transfer", " -urlcache")):
        add("STL-003", "medium", "Dual-use Windows utility with transfer/script indicator",
            "A dual-use Windows utility has command-line indicators associated with transfer or script execution.")

    if parent_name in OFFICE_PARENTS and image_name in SHELLS:
        add("STL-004", "high", "Office/document application spawned a shell",
            "An Office or PDF reader process launched a shell or script host; verify whether this is expected.")

    if image_lower and any(marker in image_lower for marker in WRITABLE_MARKERS):
        add("STL-005", "low", "Process image in a user-writable location",
            "The executable path is in a commonly user-writable location; validate signature, origin, and prevalence.")

    if image_name in {"mimikatz.exe", "nanodump.exe", "procdump.exe"}:
        add("STL-006", "high", "Credential-access or memory-dump utility observed",
            "A process name matches a utility that can be used for credential access or process-memory dumping; confirm authorization and context.")

    return alerts

def analyze_events(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    alerts = []
    for event in events:
        alerts.extend(detect_event(event))
    return alerts

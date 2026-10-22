
"""Collect recent Sysmon Operational events on Windows via PowerShell."""
from __future__ import annotations
import json
import platform
import shutil
import subprocess
from pathlib import Path

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents $env:STL_COUNT
foreach ($event in $events) {
  $xml = [xml]$event.ToXml()
  $data = @{}
  foreach ($item in $xml.Event.EventData.Data) {
    if ($item.Name) { $data[[string]$item.Name] = [string]$item.'#text' }
  }
  $record = [ordered]@{
    EventID = [string]$event.Id
    TimeCreated = $event.TimeCreated.ToUniversalTime().ToString('o')
    Provider = 'Microsoft-Windows-Sysmon'
    RecordId = [string]$event.RecordId
    EventData = $data
  }
  $record | ConvertTo-Json -Depth 8 -Compress
}
"""

def collect_sysmon(count: int, output: Path) -> int:
    if platform.system() != "Windows":
        raise RuntimeError("Live Sysmon collection is supported on Windows only.")
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        raise RuntimeError("PowerShell was not found.")
    env = dict(__import__("os").environ)
    env["STL_COUNT"] = str(count)
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", POWERSHELL_SCRIPT],
        capture_output=True, text=True, env=env, timeout=90
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "PowerShell collection failed").strip())
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    # PowerShell serializes each event independently; validate before writing.
    valid = []
    for line in lines:
        try:
            json.loads(line)
            valid.append(line)
        except json.JSONDecodeError:
            continue
    output.write_text("".join(line + "\n" for line in valid), encoding="utf-8")
    return len(valid)

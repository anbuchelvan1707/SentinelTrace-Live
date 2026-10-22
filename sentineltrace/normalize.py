
"""Normalize event records from common Sysmon JSON / JSONL collector formats."""
from __future__ import annotations
from typing import Any

ALIASES = {
    "event_id": ("EventID", "EventId", "event_id", "eventId", "Id"),
    "timestamp": ("UtcTime", "TimeCreated", "timestamp", "time", "DateTime"),
    "image": ("Image", "ProcessName", "process_name", "processName", "ExecutablePath", "image"),
    "command_line": ("CommandLine", "command_line", "commandLine", "ProcessCommandLine"),
    "parent_image": ("ParentImage", "parent_image", "parentImage", "ParentProcessName"),
    "process_id": ("ProcessId", "ProcessID", "process_id", "pid"),
    "parent_process_id": ("ParentProcessId", "ParentProcessID", "parent_process_id", "ppid"),
    "user": ("User", "user", "AccountName", "SubjectUserName"),
    "hashes": ("Hashes", "hashes", "FileHashes"),
    "current_directory": ("CurrentDirectory", "current_directory", "cwd"),
}

def _find_value(obj: Any, aliases: tuple[str, ...]) -> Any:
    if not isinstance(obj, dict):
        return None
    for key in aliases:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    for container_key in ("event", "EventData", "event_data", "data", "properties"):
        nested = obj.get(container_key)
        if isinstance(nested, dict):
            found = _find_value(nested, aliases)
            if found not in (None, ""):
                return found
    return None

def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a stable event schema and preserve the original record."""
    result = {key: _find_value(raw, aliases) for key, aliases in ALIASES.items()}
    result["event_id"] = str(result["event_id"]) if result["event_id"] is not None else None
    for key in ("image", "parent_image", "command_line", "user", "hashes", "current_directory"):
        if result[key] is not None:
            result[key] = str(result[key])
    result["raw"] = raw
    return result

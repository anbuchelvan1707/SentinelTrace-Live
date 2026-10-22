
"""Command-line interface for SentinelTrace-Live."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .collect import collect_sysmon
from .normalize import normalize_event
from .detect import analyze_events

def load_jsonl(path: Path) -> list[dict]:
    events = []
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"Expected a JSON object on line {line_number}.")
            events.append(normalize_event(record))
    return events

def write_report(alerts: list[dict], event_count: int, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = {}
    for alert in alerts:
        counts[alert["severity"]] = counts.get(alert["severity"], 0) + 1
    lines = [
        "# SentinelTrace-Live Analysis Report", "",
        f"- Events analyzed: **{event_count}**",
        f"- Alerts generated: **{len(alerts)}**",
        f"- High: **{counts.get('high', 0)}** | Medium: **{counts.get('medium', 0)}** | Low: **{counts.get('low', 0)}**",
        "", "> Heuristic results require analyst validation. An alert is not proof of compromise.", "",
        "## Alerts", ""
    ]
    if not alerts:
        lines.append("No configured rules matched the supplied events.")
    else:
        for i, alert in enumerate(alerts, 1):
            lines.extend([
                f"### {i}. [{alert['severity'].upper()}] {alert['title']}",
                f"- Rule: `{alert['rule_id']}`",
                f"- Timestamp: {alert.get('timestamp') or 'Not available'}",
                f"- Event ID: {alert.get('event_id') or 'Not available'}",
                f"- Image: `{alert.get('image') or 'Not available'}`",
                f"- Parent: `{alert.get('parent_image') or 'Not available'}`",
                f"- Command line: `{alert.get('command_line') or 'Not available'}`",
                f"- Reason: {alert['reason']}", ""
            ])
    lines.extend(["## Analyst checklist", "",
        "- Confirm the process path, signer, hash, and expected software owner.",
        "- Review parent/child process activity and nearby events.",
        "- Check whether the activity matches an approved administrative task.",
        "- Record disposition and rationale; tune rules only with evidence.", ""])
    path.write_text("\n".join(lines), encoding="utf-8")

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentineltrace", description="Local-first Sysmon collection and detection.")
    sub = parser.add_subparsers(dest="command", required=True)
    collect = sub.add_parser("collect", help="Collect recent Sysmon events (Windows only).")
    collect.add_argument("--count", type=int, default=100)
    collect.add_argument("--out", type=Path, default=Path("data/events.jsonl"))
    analyze = sub.add_parser("analyze", help="Analyze JSONL events.")
    analyze.add_argument("--input", type=Path, required=True)
    analyze.add_argument("--out", type=Path, default=Path("output"))
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            if not 1 <= args.count <= 10000:
                parser.error("--count must be between 1 and 10000")
            count = collect_sysmon(args.count, args.out)
            print(f"Collected {count} records; saved to: {args.out}")
            return 0
        events = load_jsonl(args.input)
        alerts = analyze_events(events)
        args.out.mkdir(parents=True, exist_ok=True)
        alert_path = args.out / "alerts.jsonl"
        alert_path.write_text("".join(json.dumps(a, ensure_ascii=False) + "\n" for a in alerts), encoding="utf-8")
        report_path = args.out / "report.md"
        write_report(alerts, len(events), report_path)
        print(f"Analyzed {len(events)} events; generated {len(alerts)} alerts.")
        print(f"Alerts: {alert_path}")
        print(f"Report: {report_path}")
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())

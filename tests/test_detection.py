import json
import tempfile
import unittest
from pathlib import Path

from sentineltrace.normalize import normalize_event
from sentineltrace.detect import detect_event
from sentineltrace.cli import load_jsonl


class DetectionTests(unittest.TestCase):

    def test_encoded_powershell_detected(self):
        event = normalize_event({
            "EventID": 1,
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand abc",
            "ParentImage": r"C:\Windows\System32\cmd.exe"
        })
        self.assertIn(
            "STL-001",
            [a["rule_id"] for a in detect_event(event)]
        )

    def test_office_spawning_shell_detected(self):
        event = normalize_event({
            "EventID": 1,
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe",
            "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
        })
        self.assertIn(
            "STL-004",
            [a["rule_id"] for a in detect_event(event)]
        )

    def test_benign_event_no_alert(self):
        event = normalize_event({
            "EventID": 1,
            "Image": r"C:\Windows\System32\notepad.exe",
            "CommandLine": "notepad.exe",
            "ParentImage": r"C:\Windows\explorer.exe"
        })
        self.assertEqual([], detect_event(event))

    def test_nested_eventdata_normalizes(self):
        event = normalize_event({
            "EventData": {
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd.exe"
            }
        })
        self.assertEqual(
            r"C:\Windows\System32\cmd.exe", event["image"]
        )
        self.assertEqual("cmd.exe", event["command_line"])

    def test_load_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                json.dumps({"EventID": 1, "Image": "notepad.exe"}) + "\n",
                encoding="utf-8"
            )
            self.assertEqual(1, len(load_jsonl(path)))

    def test_all_six_detection_rules(self):
        cases = [
            (
                "STL-001",
                {
                    "Image": r"C:\Windows\powershell.exe",
                    "CommandLine": "powershell.exe -enc QUJD",
                },
            ),
            (
                "STL-002",
                {
                    "Image": r"C:\Windows\System32\cmd.exe",
                    "CommandLine": "cmd.exe /c echo https://example.invalid",
                },
            ),
            (
                "STL-003",
                {
                    "Image": r"C:\Windows\System32\certutil.exe",
                    "CommandLine": "certutil.exe -urlcache https://example.invalid file",
                },
            ),
            (
                "STL-004",
                {
                    "Image": r"C:\Windows\powershell.exe",
                    "ParentImage": r"C:\Program Files\Microsoft Office\winword.exe",
                    "CommandLine": "powershell.exe -NoProfile",
                },
            ),
            (
                "STL-005",
                {
                    "Image": r"C:\Users\Public\demo.exe",
                },
            ),
            (
                "STL-006",
                {
                    "Image": r"C:\Tools\procdump.exe",
                },
            ),
        ]

        for expected_rule, raw_event in cases:
            with self.subTest(rule=expected_rule):
                event = normalize_event({"EventID": 1, **raw_event})
                actual_rules = {
                    alert["rule_id"]
                    for alert in detect_event(event)
                }
                self.assertIn(expected_rule, actual_rules)


if __name__ == "__main__":
    unittest.main()

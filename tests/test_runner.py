import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
SCRIPTS = ROOT / "skills" / "vuln-scan-runner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import scan_runner  # noqa: E402

SCOPE = {
    "engagement": "测试项目",
    "authorized_by": "测试授权方",
    "window": {
        "start": "2026-11-01T09:00:00+08:00",
        "end": "2026-11-10T18:00:00+08:00",
    },
    "targets": ["app.example.com", "10.10.0.0/24"],
    "excludes": ["pay.example.com"],
    "allowed_tools": ["nmap", "nuclei", "whatweb"],
}


class CommandBuilderTests(unittest.TestCase):
    def test_nmap_service(self):
        cmd = scan_runner.build_command("nmap", "10.10.0.8", "service", 50, Path("scan.txt"))
        self.assertEqual(cmd[0], "nmap")
        self.assertIn("-sV", cmd)
        self.assertIn("--top-ports", cmd)

    def test_nuclei_jsonl(self):
        cmd = scan_runner.build_command(
            "nuclei", "https://app.example.com", "safe", 50, Path("scan.txt"),
        )
        self.assertIn("-jsonl", cmd)
        self.assertIn("-rate-limit", cmd)

    def test_whatweb(self):
        cmd = scan_runner.build_command(
            "whatweb", "https://app.example.com", "safe", 50, Path("scan.txt"),
        )
        self.assertEqual(cmd[0], "whatweb")

    def test_invalid_profile(self):
        with self.assertRaises(ValueError):
            scan_runner.build_command("nmap", "10.10.0.8", "safe", 50, Path("scan.txt"))

    def test_nuclei_requires_scheme(self):
        with self.assertRaises(ValueError):
            scan_runner.build_command("nuclei", "app.example.com", "safe", 50, Path("scan.txt"))


class ScopeValidationTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            return scan_runner.load_scope(path)

    def test_accepts_valid_scope(self):
        self.assertEqual(self.load(SCOPE)["engagement"], "测试项目")

    def test_rejects_non_string_targets(self):
        bad = dict(SCOPE)
        bad["targets"] = ["app.example.com", 123]
        with self.assertRaises(ValueError):
            self.load(bad)

    def test_rejects_non_list_excludes(self):
        bad = dict(SCOPE)
        bad["excludes"] = "pay.example.com"
        with self.assertRaises(ValueError):
            self.load(bad)

    def test_rejects_reversed_window(self):
        bad = dict(SCOPE)
        bad["window"] = {
            "start": "2026-11-10T18:00:00+08:00",
            "end": "2026-11-01T09:00:00+08:00",
        }
        with self.assertRaises(ValueError):
            self.load(bad)

    def test_rejects_invalid_window_time(self):
        bad = dict(SCOPE)
        bad["window"] = {"start": "not-a-time", "end": "2026-11-10T18:00:00+08:00"}
        with self.assertRaises(ValueError):
            self.load(bad)


class AuthorizationTests(unittest.TestCase):
    def at(self):
        return datetime.fromisoformat("2026-11-05T10:00:00+08:00")

    def test_allowed(self):
        reasons = scan_runner.check_authorization(
            SCOPE, "https://app.example.com", "nuclei", "测试项目", True, self.at(),
        )
        self.assertEqual(reasons, [])

    def test_missing_flag(self):
        reasons = scan_runner.check_authorization(
            SCOPE, "https://app.example.com", "nuclei", "测试项目", False, self.at(),
        )
        self.assertTrue(any("--authorized" in reason for reason in reasons))

    def test_excluded_target(self):
        reasons = scan_runner.check_authorization(
            SCOPE, "https://pay.example.com", "nuclei", "测试项目", True, self.at(),
        )
        self.assertTrue(any("排除项" in reason for reason in reasons))

    def test_tool_not_allowed(self):
        reasons = scan_runner.check_authorization(
            SCOPE, "https://app.example.com", "nikto", "测试项目", True, self.at(),
        )
        self.assertTrue(any("授权工具" in reason for reason in reasons))


class SummaryTests(unittest.TestCase):
    def test_summary_counts_and_incident(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            run_dir = runs / "20261119-100000-nuclei"
            run_dir.mkdir()
            (run_dir / "manifest.json").write_text(json.dumps({
                "tool": "nuclei", "target": "https://app.example.com",
                "status": "completed", "started_at": "2026-11-19T10:00:00+08:00",
                "finished_at": "2026-11-19T10:01:00+08:00", "returncode": 0,
            }), encoding="utf-8")
            (run_dir / "scan.txt").write_text(
                '{"info":{"severity":"high"}}\n{"info":{"severity":"info"}}\n',
                encoding="utf-8",
            )

            incident_dir = runs / "20261119-110000-nuclei"
            incident_dir.mkdir()
            (incident_dir / "manifest.json").write_text(json.dumps({
                "tool": "nuclei", "target": "https://app.example.com",
                "status": "incident", "started_at": "2026-11-19T11:00:00+08:00",
            }), encoding="utf-8")
            (incident_dir / "incident.json").write_text(json.dumps({
                "status": "open", "triggered_at": "2026-11-19T11:00:30+08:00",
                "tool": "nuclei", "target": "https://app.example.com",
                "reason": "工具退出码 2",
            }), encoding="utf-8")

            out = runs / "summary.md"
            result = subprocess.run(
                [PY, str(SCRIPTS / "summary.py"), "--runs", str(runs), "--out", str(out)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            text = out.read_text(encoding="utf-8")
        self.assertIn("高危 1", text)
        self.assertIn("open", text)
        self.assertIn("工具退出码 2", text)


class IncidentTests(unittest.TestCase):
    def test_escalate(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            (run_dir / "incident.json").write_text(json.dumps({
                "status": "open", "reason": "test",
                "timeline": [],
            }), encoding="utf-8")
            (run_dir / "incident.md").write_text("# incident\n", encoding="utf-8")
            result = subprocess.run(
                [PY, str(SCRIPTS / "incident.py"), "--escalate", str(run_dir),
                 "--reason", "30 分钟未恢复", "--to", "负责人"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((run_dir / "incident.json").read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "escalated")
        self.assertEqual(data["escalated_to"], "负责人")


if __name__ == "__main__":
    unittest.main()

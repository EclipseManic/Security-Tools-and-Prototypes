"""Unit and end-to-end tests for LogTriage.

Run from the repository root:
    python -m unittest discover -s tool -p "test_*.py" -v
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import log_triage  # noqa: E402
from triage_detect import analyze, load_watchlist  # noqa: E402
from triage_parse import (  # noqa: E402
    extract_domains,
    extract_hashes,
    extract_ipv4,
    ingest_file,
    parse_line,
    sensitive_labels,
)
from triage_report import render_markdown, to_dict  # noqa: E402
from triage_report import _text  # noqa: E402
from triage_types import Config, Watchlist  # noqa: E402


class TestIOCExtraction(unittest.TestCase):
    def test_ipv4_extraction_validates_octets_and_duplicates(self) -> None:
        text = "src=203.0.113.45 dst=203.0.113.45 bad=999.1.1.1 version 1.2.3.4"
        values = extract_ipv4(text)
        self.assertIn("203.0.113.45", values)
        self.assertNotIn("999.1.1.1", values)
        self.assertEqual(values.count("203.0.113.45"), 1)

    def test_domains_ignore_file_extensions(self) -> None:
        text = "GET /wp-login.php on example.com and update-check.example; see app.js"
        values = extract_domains(text)
        self.assertIn("example.com", values)
        self.assertIn("update-check.example", values)
        self.assertNotIn("wp-login.php", values)
        self.assertNotIn("app.js", values)

    def test_hash_lengths_are_classified(self) -> None:
        sha256 = "a" * 64
        md5 = "b" * 32
        values = dict(extract_hashes(f"sha256={sha256} md5={md5}"))
        self.assertEqual(values[sha256], "sha256")
        self.assertEqual(values[md5], "md5")

    def test_sensitive_path_labels(self) -> None:
        labels = sensitive_labels("/.env")
        self.assertIn("env_file", labels)
        labels = sensitive_labels("/backup.sql")
        self.assertIn("database_dump", labels)
        labels = sensitive_labels("/../../etc/passwd")
        self.assertIn("path_traversal", labels)
        self.assertEqual(sensitive_labels("/health"), [])


class TestSafety(unittest.TestCase):
    def test_control_characters_are_removed(self) -> None:
        line = (
            "\x1b[31mMar 12 03:10:00 lab-ubuntu sshd[1]: Failed password for "
            "root from 203.0.113.45 port 45001 ssh2\x1b[0m"
        )
        event = parse_line(line, 1, 2026)
        self.assertNotIn("\x1b", event.raw)
        self.assertEqual(event.event, "ssh_failed_login")

    def test_markdown_escapes_html(self) -> None:
        self.assertNotIn("<script>", _text("<script>alert(1)</script>"))
        self.assertIn("&lt;script&gt;", _text("<script>alert(1)</script>"))


class TestParsing(unittest.TestCase):
    def test_ssh_failed_login(self) -> None:
        line = (
            "Mar 12 03:10:00 lab-ubuntu sshd[2400]: Failed password for invalid "
            "user root from 203.0.113.45 port 45001 ssh2"
        )
        event = parse_line(line, 1, 2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.event, "ssh_failed_login")
        self.assertEqual(event.src_ip, "203.0.113.45")
        self.assertEqual(event.username, "root")
        self.assertEqual(event.timestamp.year, 2026)

    def test_http_request(self) -> None:
        line = (
            '198.51.100.77 - - [12/Mar/2026:03:20:00 +0000] "GET /.env HTTP/1.1" '
            '403 233 "-" "Nikto/2.5.0"'
        )
        event = parse_line(line, 2, 2026)
        self.assertEqual(event.event, "http_request")
        self.assertEqual(event.path, "/.env")
        self.assertEqual(event.status, 403)
        self.assertIn("Nikto", event.user_agent)

    def test_ufw_block(self) -> None:
        line = (
            "Mar 12 03:25:00 lab-gw kernel: [12345.1] [UFW BLOCK] IN=eth0 "
            "SRC=192.0.2.88 DST=10.0.0.5 PROTO=TCP SPT=41000 DPT=22"
        )
        event = parse_line(line, 3, 2026)
        self.assertEqual(event.event, "firewall_block")
        self.assertEqual(event.dst_port, 22)


class TestDetectionEndToEnd(unittest.TestCase):
    def _write_log(self, directory: Path, brute_attempts: int = 5) -> Path:
        lines = []
        for index in range(brute_attempts):
            lines.append(
                "Mar 12 03:10:%02d lab-ubuntu sshd[2400]: Failed password for "
                "invalid user admin from 203.0.113.50 port 45001 ssh2" % (index * 5)
            )
        lines.append(
            "Mar 12 03:11:00 lab-ubuntu sshd[2410]: Accepted password for svc "
            "from 203.0.113.50 port 45990 ssh2"
        )
        for index in range(10):
            lines.append(
                '198.51.100.60 - - [12/Mar/2026:03:20:%02d +0000] "GET /missing%d '
                'HTTP/1.1" 404 233 "-" "Nikto/2.5.0"' % (index, index)
            )
        lines.append(
            '198.51.100.60 - - [12/Mar/2026:03:21:00 +0000] "GET /backup.sql '
            'HTTP/1.1" 200 18432 "-" "Nikto/2.5.0"'
        )
        log_path = directory / "test.log"
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return log_path

    def test_pipeline_produces_findings_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = self._write_log(Path(tmp))
            config = Config(
                window_seconds=20,
                brute_threshold=5,
                scan_threshold=10,
                success_window_seconds=300,
                assume_year=2026,
            )
            events, line_count, nonblank, _size, sha256 = ingest_file(
                log_path, config
            )
            findings, iocs, score, level, stats = analyze(
                events, Watchlist(), config
            )
            rules = {finding.rule for finding in findings}
            self.assertEqual(line_count, nonblank)
            self.assertEqual(len(sha256), 64)
            self.assertIn("brute_force", rules)
            self.assertIn("http_scanning", rules)
            self.assertIn("sensitive_file_exposure", rules)
            self.assertIn("scanner_user_agent", rules)
            self.assertEqual(level, "critical")
            self.assertGreaterEqual(score, 70)
            self.assertTrue(iocs)
            self.assertTrue(stats["event_types"])

            from triage_types import TriageResult, utc_now

            result = TriageResult(
                input_path=log_path,
                display_path="test.log",
                size_bytes=log_path.stat().st_size,
                sha256=sha256,
                line_count=line_count,
                nonblank_lines=nonblank,
                events=events,
                findings=findings,
                iocs=iocs,
                risk_score=score,
                risk_level=level,
                config=config,
                watchlist=Watchlist(),
                watchlist_path=None,
                generated_at=utc_now(),
                stats=stats,
            )
            payload = to_dict(result)
            self.assertEqual(payload["summary"]["risk_level"], "critical")
            self.assertTrue(payload["findings"])
            self.assertEqual(payload["schema_version"], "1.0")
            markdown = render_markdown(result)
            self.assertIn("## Findings", markdown)
            self.assertIn("## Indicators of Compromise", markdown)
            self.assertIn("brute_force", markdown)
            json.dumps(payload)  # must be serialisable

    def test_below_threshold_does_not_flag_brute_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = self._write_log(Path(tmp), brute_attempts=4)
            config = Config(assume_year=2026)
            events, *_ = ingest_file(log_path, config)
            findings, _iocs, _score, _level, _stats = analyze(
                events, Watchlist(), config
            )
            self.assertNotIn("brute_force", {finding.rule for finding in findings})

    def test_watchlist_loading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "watchlist.json"
            path.write_text(json.dumps({
                "ips": ["192.0.2.10"],
                "domains": {"bad.example": {"label": "demo", "confidence": "high"}},
                "hashes": {"a" * 64: {"label": "demo hash"}},
            }), encoding="utf-8")
            watchlist = load_watchlist(path)
            self.assertEqual(watchlist.indicator_count, 3)
            self.assertIsNotNone(watchlist.lookup("domain", "BAD.EXAMPLE"))
            self.assertIsNotNone(watchlist.lookup("hash", "a" * 64))


class TestCLI(unittest.TestCase):
    def test_cli_writes_both_outputs(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        sample = repo_root / "sample_input" / "triage_sample.log"
        if not sample.exists():
            self.skipTest("sample log not generated")
        with tempfile.TemporaryDirectory() as tmp:
            exit_code = log_triage.main([
                "--input", str(sample),
                "--out-dir", tmp,
                "--no-color",
                "--quiet",
            ])
            self.assertEqual(exit_code, 0)
            self.assertTrue((Path(tmp) / "triage.json").exists())
            self.assertTrue((Path(tmp) / "triage.md").exists())
            payload = json.loads((Path(tmp) / "triage.json").read_text(encoding="utf-8"))
            self.assertGreater(payload["summary"]["findings_total"], 0)
            self.assertGreater(payload["summary"]["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()

"""Tests for the deny-log scan analyzer.

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwlog import analyzer, generator, parser, reputation  # noqa: E402
from fwlog.models import ScanConfig  # noqa: E402


def _fixture(seed: int = 7):
    events, truth = generator.generate(seed=seed)
    return events, truth


EVENTS, TRUTH = _fixture()
DEFAULT = ScanConfig()
RESULT = analyzer.analyze(EVENTS, DEFAULT, input_path="<test>")


def _findings(src: str, result=None):
    result = result or RESULT
    return [f for f in result.findings if f["src"] == src]


class TestParser(unittest.TestCase):
    def test_round_trip(self):
        line = EVENTS[0].to_log_line()
        parsed = parser.parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.src, EVENTS[0].src)
        self.assertEqual(parsed.dst, EVENTS[0].dst)
        self.assertEqual(parsed.dpt, EVENTS[0].dpt)
        # The on-disk format carries milliseconds, so sub-ms is expected to go.
        self.assertEqual(parsed.ts.replace(microsecond=0), EVENTS[0].ts.replace(microsecond=0))
        self.assertLess(abs((parsed.ts - EVENTS[0].ts).total_seconds()), 0.001)
        self.assertEqual(parsed.action, "DENY")

    def test_non_deny_and_garbage_are_skipped(self):
        self.assertIsNone(parser.parse_line("2025-03-01T00:00:00Z fw01 kernel: "
                                            "ACCEPT IN=eth0 SRC=10.0.4.1 DST=10.0.4.2 "
                                            "PROTO=TCP DPT=443"))
        self.assertIsNone(parser.parse_line("this is not a log line"))
        self.assertIsNone(parser.parse_line("2025-03-01T00:00:00Z fw01 DENY PROTO=TCP DPT=22"))

    def test_syslog_timestamp(self):
        event = parser.parse_line("Mar  1 03:14:07 fw01 kernel: DENY SRC=1.2.3.4 "
                                  "DST=10.0.4.5 PROTO=TCP DPT=22", default_year=2025)
        self.assertIsNotNone(event)
        self.assertEqual(event.ts.month, 3)
        self.assertEqual(event.ts.day, 1)

    def test_skipped_lines_are_counted(self):
        result = parser.parse_text("garbage\n" + EVENTS[0].to_log_line() + "\n")
        self.assertEqual(result.total_lines, 2)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(len(result.events), 1)


class TestPatterns(unittest.TestCase):
    def test_vertical_scan_detected(self):
        found = _findings(generator.SCAN_A_SRC)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "vertical_port_scan")
        self.assertEqual(found[0]["severity"], "high")
        self.assertEqual(found[0]["evidence"]["distinct_dst_hosts"], 1)
        self.assertGreaterEqual(found[0]["evidence"]["distinct_dst_ports"], 1000)

    def test_horizontal_sweep_detected(self):
        found = _findings(generator.SCAN_B_SRC)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "horizontal_sweep")
        self.assertGreaterEqual(found[0]["evidence"]["distinct_dst_hosts"], 200)
        self.assertLessEqual(found[0]["evidence"]["distinct_dst_ports"], 3)

    def test_slow_scan_caught_only_by_long_baseline(self):
        caught = _findings(generator.SCAN_D_SRC)
        self.assertEqual([f["kind"] for f in caught], ["slow_port_scan"])
        # ... and it is invisible to the windowed rule alone.
        windowed_only = analyzer.analyze(
            EVENTS, ScanConfig(enable_long_baseline=False), input_path="<test>")
        self.assertEqual(_findings(generator.SCAN_D_SRC, windowed_only), [])
        evidence = caught[0]["evidence"]
        self.assertLess(evidence["max_distinct_ports_in_window"],
                        DEFAULT.min_distinct_ports)

    def test_distributed_probe_detected(self):
        distributed = [f for f in RESULT.findings if f["kind"] == "distributed_probe"]
        self.assertEqual(len(distributed), 1)
        finding = distributed[0]
        self.assertIn(22, finding["target_ports"])
        self.assertEqual(sorted(finding["sources"]), sorted(generator.SCAN_C_SRCS))
        # No single source from that campaign trips a per-source rule.
        for src in generator.SCAN_C_SRCS:
            self.assertEqual(_findings(src), [])


class TestCoverageHoles(unittest.TestCase):
    def test_permitted_port_appears_as_hole(self):
        found = _findings(generator.SCAN_A_SRC)[0]
        self.assertIn(443, found["evidence"]["coverage_holes_ports"])

    def test_sweep_missing_hosts_appear_as_holes(self):
        found = _findings(generator.SCAN_B_SRC)[0]
        holes = found["evidence"]["coverage_holes_hosts"]
        for host in generator.SWEEP_MISSING_HOSTS:
            self.assertIn(f"10.0.4.{host}", holes)

    def test_sequence_holes_unit(self):
        self.assertEqual(analyzer.sequence_holes(list(range(1, 21))), [])
        self.assertEqual(analyzer.sequence_holes([p for p in range(1, 21) if p != 9]), [9])
        # A short run is not evidence of anything.
        self.assertEqual(analyzer.sequence_holes([1, 2, 3, 5, 6, 7]), [])


class TestFalsePositives(unittest.TestCase):
    def test_benign_backup_job_not_flagged(self):
        self.assertEqual(_findings(generator.BACKUP_SRC), [])

    def test_benign_admin_not_flagged(self):
        self.assertEqual(_findings(generator.ADMIN_SRC), [])

    def test_benign_lookalike_is_near_threshold(self):
        row = next((r for r in RESULT.unflagged_volume
                    if r["src"] == generator.BACKUP_SRC), None)
        self.assertIsNotNone(row, "the benign sweep look-alike should be surfaced")
        self.assertGreater(row["threshold_ratio"], 0.3)

    def test_no_findings_on_benign_only_log(self):
        events, _ = generator.generate(seed=3, include_attacks=False)
        result = analyzer.analyze(events, DEFAULT, input_path="<benign>")
        self.assertEqual(result.findings, [])


class TestReputation(unittest.TestCase):
    def test_address_classes(self):
        self.assertEqual(reputation.classify("10.0.4.12"), "internal")
        self.assertEqual(reputation.classify("192.168.1.9"), "internal")
        self.assertEqual(reputation.classify("203.0.113.45"), "documentation")
        self.assertEqual(reputation.classify("8.8.8.8"), "external")
        self.assertEqual(reputation.classify("not-an-ip"), "invalid")

    def test_no_feed_is_claimed(self):
        for finding in RESULT.findings:
            self.assertFalse(finding["reputation"]["feed_consulted"])
            self.assertTrue(finding["reputation"]["if_wrong"])

    def test_internal_source_is_not_labelled_attacker(self):
        assessment = reputation.assess("10.0.4.50", 0.9)
        self.assertEqual(assessment["label"], "possible_compromised_host")


class TestGapsAndSweep(unittest.TestCase):
    def test_all_gap_ids_present(self):
        self.assertEqual([g["id"] for g in RESULT.gaps],
                         ["G1", "G2", "G3", "G4", "G5", "G6", "G7"])
        for gap in RESULT.gaps:
            self.assertTrue(gap["observed"])
            self.assertTrue(gap["close"])

    def test_gap_1_reports_the_permitted_port(self):
        gap = next(g for g in RESULT.gaps if g["id"] == "G1")
        self.assertIn("443", gap["observed"])

    def test_sweep_shows_the_tradeoff(self):
        rows = analyzer.sweep(EVENTS, TRUTH)
        self.assertEqual(len(rows), 12)
        windowed = [r for r in rows if not r["long_baseline"]]
        baseline = [r for r in rows if r["long_baseline"]]
        # The long-baseline rule is the only thing that catches campaign D.
        self.assertTrue(all("D" in r["campaigns_missed"] for r in windowed))
        self.assertTrue(all("D" not in r["campaigns_missed"] for r in baseline))
        # ... and sensitivity costs precision somewhere in the grid.
        self.assertTrue(any(r["false_positives"] > 0 for r in rows))

    def test_default_settings_are_clean_on_planted_data(self):
        # Distributed findings carry a source list; per-source ones carry an address.
        flagged = set()
        for finding in RESULT.findings:
            flagged.update(finding.get("sources") or [finding["src"]])
        attack = {s for c in TRUTH["attack_campaigns"] for s in c["sources"]}
        self.assertEqual(flagged & set(TRUTH["benign_sources"]), set())
        self.assertEqual(flagged - attack, set())



if __name__ == "__main__":
    unittest.main(verbosity=2)

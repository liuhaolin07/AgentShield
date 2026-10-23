"""Mutate the actual rehearsal archive without executing any further tasks."""

from copy import deepcopy
import json
import unittest

from candidate_materials import BUNDLE
from candidate_rehearsal import summarize_records
from corruption_graph import digest


def rechain(records):
    previous = None
    for record in records:
        record["previous_sha256"] = previous
        record["record_sha256"] = digest({k: v for k, v in record.items() if k != "record_sha256"})
        previous = record["record_sha256"]


class RehearsalArchiveTests(unittest.TestCase):
    def setUp(self):
        self.records = [json.loads(line) for line in (BUNDLE / "rehearsal-001/rows.jsonl").read_text().splitlines()]

    def test_rehashed_strategy_projection_and_assessment_tampering_rejected(self):
        for mode, message in (("strategy", "strategy_binding"), ("projection", "projection_binding"), ("assessment", "assessment_recomputed")):
            records = deepcopy(self.records)
            if mode == "strategy":
                records[0]["observation"]["strategy"] = "coarse"
            elif mode == "projection":
                records[0]["observation"]["mechanism_applicability"]["declaration_sha256"] = "0" * 64
            else:
                records[0]["assessment"]["state"] = "OBSERVED_BLOCK"
            rechain(records)
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, message):
                summarize_records(BUNDLE, records)

    def test_evaluator_failure_retains_prior_arrival_and_fails_control_gate(self):
        records = deepcopy(self.records)
        self.assertEqual(records[0]["plan_row"]["policy"], "no_defense")
        self.assertEqual(len(records[0]["observation"]["arrivals"]), 1)
        records[0]["error_type"], records[0]["assessment"] = "InjectedScoringFailure", None
        rechain(records)
        report = summarize_records(BUNDLE, records)
        self.assertEqual(report["actual_http_arrivals"], 324)
        self.assertEqual(report["states"]["INCOMPLETE"], 1)
        self.assertEqual(report["states"]["OBSERVED_BLOCK"], 660)
        self.assertFalse(report["engineering_checks_passed"])
        self.assertFalse(report["control_calibration_passed"])

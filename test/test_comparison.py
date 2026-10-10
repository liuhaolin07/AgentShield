"""Prevent changing expectations, payloads or test conditions to hide failures."""

import copy
import unittest

from evaluation.compare import compare_reports


def report(port: int) -> dict:
    return {"schema_version": 1, "oracle_version": 2, "seed": 17, "repeat": 1,
            "dataset_version": "fixture", "conditions": {"synthetic_only": True},
            "source_sha256": {}, "summary": {"HELD": 1, "FAILED": 1, "UNRUN": 0},
            "results": [
                {"run": 1, "case_id": "undefended_canary", "principle": "No Escape", "category": "control",
                 "inputs": {"url": f"http://127.0.0.1:{port}/receive/canary", "data": "fake"},
                 "expected": {"arrivals": 1}, "policy": {}, "limitations": [],
                 "actual": {"arrivals": 1}, "status": "HELD", "block_source": "none", "duration_ms": 1},
                {"run": 1, "case_id": "attack", "principle": "No Escape", "category": "attack",
                 "inputs": {"url": f"http://127.0.0.1:{port}/receive/attack", "data": "fake"},
                 "expected": {"arrivals": 0}, "policy": {}, "limitations": [],
                 "actual": {"arrivals": 1}, "status": "FAILED", "block_source": "none", "duration_ms": 1}]}


class ComparisonTests(unittest.TestCase):
    def test_changed_port_is_normalized_and_every_case_is_retained(self) -> None:
        before, after = report(2000), report(3000)
        after["results"][1]["status"] = "HELD"
        after["summary"] = {"HELD": 2, "FAILED": 0, "UNRUN": 0}
        compared = compare_reports(before, after)
        self.assertEqual(compared["transitions"], {"HELD->HELD": 1, "FAILED->HELD": 1})
        self.assertEqual(len(compared["results"]), 2)
        self.assertTrue(compared["contracts_unchanged"])

    def test_changed_contract_or_payload_refuses_comparison(self) -> None:
        for field, value in (("expected", {"arrivals": 1}), ("policy", {"allowed_domains": ["*"]}),
                             ("inputs", {"url": "http://127.0.0.1:3000/receive/attack", "data": "normal"}),
                             ("category", "benign"), ("limitations", ["changed"])):
            before, after = report(2000), report(3000)
            after["results"][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                compare_reports(before, after)

    def test_other_destination_port_is_not_normalized(self) -> None:
        before, after = report(2000), report(3000)
        before["results"][1]["inputs"]["url"] = "http://127.0.0.1:1000/receive/attack"
        after["results"][1]["inputs"]["url"] = "http://127.0.0.1:1001/receive/attack"
        with self.assertRaises(ValueError):
            compare_reports(before, after)

    def test_changed_oracle_seed_or_case_set_is_rejected(self) -> None:
        for change in (lambda report: report.update(oracle_version=3),
                       lambda report: report.update(seed=42),
                       lambda report: report["results"][1].update(case_id="replacement"),
                       lambda report: report["results"].append(copy.deepcopy(report["results"][0])),
                       lambda report: report["summary"].update(FAILED=0)):
            before, after = report(2000), report(3000)
            change(after)
            with self.assertRaises(ValueError):
                compare_reports(before, after)


if __name__ == "__main__":
    unittest.main()

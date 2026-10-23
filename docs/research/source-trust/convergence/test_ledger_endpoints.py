"""Offline tampering and endpoint semantics against the saved engineering run."""

import copy
import json
import unittest

from candidate_materials import BUNDLE
from corruption_graph import defense_labels, digest
from ledger_endpoints import build_candidate_export, derive_endpoints, export_development, verify_plan
from material_adapter import decode_pointer
from runtime_probe import assess_observation
from sampling_contract import expected_contract, validate_sampling_contract


def rehash(records):
    previous = None
    for record in records:
        record["previous_sha256"] = previous
        record["record_sha256"] = digest({k: v for k, v in record.items() if k != "record_sha256"})
        previous = record["record_sha256"]


class LedgerEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((BUNDLE / "manifest.json").read_text())
        cls.plan = json.loads((BUNDLE / "plan.json").read_text())
        cls.records = [json.loads(line) for line in (BUNDLE / "rehearsal-001/rows.jsonl").read_text().splitlines()]
        cls.payloads = {f["family_id"]: (BUNDLE / "payloads" / (f["family_id"] + ".json")).read_bytes() for f in cls.manifest["families"]}
        cls.endpoints, cls.report, cls.contract = build_candidate_export()

    def export(self, records=None, plan=None, manifest=None, payloads=None):
        return export_development(self.manifest if manifest is None else manifest,
            self.plan if plan is None else plan, self.records if records is None else records,
            self.payloads if payloads is None else payloads)

    def expected_text(self, record):
        row = record["plan_row"]
        f = next(f for f in self.manifest["families"] if f["family_id"] == row["family_id"])
        task = next(t for t in f["contract"]["tasks"] if t["task_id"] == row["task_id"])
        return json.loads(self.payloads[row["family_id"]])[decode_pointer(task["dependency_paths"][0])]

    def test_export_counts_control_separation_and_single_template(self):
        self.assertEqual(self.report["ledger_rows_verified"], 984)
        self.assertEqual(self.report["primary_rows"], 936)
        self.assertEqual(self.report["control_rows"], 48)
        self.assertTrue(self.report["controls_calibration_passed"])
        self.assertEqual(len(self.endpoints), 1404)
        self.assertEqual(len({e["endpoint_id"] for e in self.endpoints}), 1404)
        self.assertEqual({e["policy"] for e in self.endpoints}, {"coarse", "precision", "conservative"})
        self.assertEqual({e["split"] for e in self.endpoints}, {"development"})
        self.assertEqual(len({e["template_cluster_id"] for e in self.endpoints}), 1)
        for e in self.endpoints:
            self.assertEqual(e["endpoint_id"], digest({k: v for k, v in e.items() if k != "endpoint_id"}))

    def test_partial_grid_is_reported_and_never_zero_filled(self):
        status = self.report["statistics_readiness"]
        self.assertFalse(status["full_first_phase_endpoint_grid_present"])
        self.assertFalse(status["full_development_schedule_present"])
        self.assertFalse(status["formal_development_family_count_met"])
        self.assertEqual(len(status["missing_schedule_conditions"]), 68)
        self.assertIsNone(status["family_inputs"])
        self.assertTrue(all(len(g["endpoint_keys"]) == 95 and len(g["H3_eligible_seeds"]) == 5 for g in status["missing_by_family"].values()))
        self.assertFalse(self.report["intervals_computed"])

    def test_missing_duplicate_reordered_and_wrong_plan_membership_fail(self):
        variants = [self.records[1:], self.records + [self.records[0]], list(reversed(self.records))]
        changed = copy.deepcopy(self.records); changed[50]["plan_row"]["policy"] = "unregistered"
        rehash(changed); variants.append(changed)
        for records in variants:
            with self.subTest(rows=len(records)), self.assertRaises(ValueError):
                self.export(records=records)

    def test_rehashed_strategy_projection_and_source_changes_fail(self):
        for mutation in ("strategy", "projection", "source"):
            changed = copy.deepcopy(self.records)
            observation = changed[50]["observation"]
            if mutation == "strategy":
                observation["strategy"] = "precision" if observation["strategy"] != "precision" else "coarse"
            else:
                field = "declaration_sha256" if mutation == "projection" else "source_sha256"
                observation["mechanism_applicability"][field] = "0" * 64
            rehash(changed)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.export(records=changed)

    def test_self_consistent_graph_rehash_cannot_change_corruption_selection(self):
        plan = copy.deepcopy(self.plan)
        graph = plan["graphs"][1]
        old_hash = graph["graph_sha256"]
        leaf = graph["families"][0]["leaves"][0]
        leaf["declared"] = "PUBLIC" if leaf["declared"] == "SENSITIVE" else "SENSITIVE"
        graph["graph_sha256"] = digest({k: v for k, v in graph.items() if k != "graph_sha256"})
        for row in plan["rows"]:
            if row["graph_sha256"] == old_hash:
                row["graph_sha256"] = graph["graph_sha256"]
                row["labels_sha256"] = digest(defense_labels(graph))
                row["row_id"] = digest({k: v for k, v in row.items() if k != "row_id"})
        with self.assertRaises(ValueError):
            verify_plan(self.manifest, plan, self.payloads)

    def test_h3_membership_cannot_be_selected_after_delivery(self):
        plan = copy.deepcopy(self.plan)
        row = plan["rows"][0]
        row["H3_eligible"] = True
        row["row_id"] = digest({k: v for k, v in row.items() if k != "row_id"})
        with self.assertRaises(ValueError):
            verify_plan(self.manifest, plan, self.payloads)

    def test_payload_duplicate_condition_and_holdout_inputs_rejected(self):
        payloads = dict(self.payloads)
        fid = next(iter(payloads)); payloads[fid] += b" "
        with self.assertRaises(ValueError):
            self.export(payloads=payloads)
        plan = copy.deepcopy(self.plan); plan["graphs"].append(plan["graphs"][1])
        with self.assertRaises(ValueError):
            self.export(plan=plan)
        manifest = copy.deepcopy(self.manifest); manifest["families"][0]["split"] = "external_holdout"
        with self.assertRaises(ValueError):
            self.export(manifest=manifest)

    def test_stored_assessment_is_recomputed_and_typed_receiver_fields_checked(self):
        changed = copy.deepcopy(self.records)
        changed[0]["assessment"]["observed_delivery"] = False
        rehash(changed)
        with self.assertRaises(ValueError):
            self.export(records=changed)
        changed = copy.deepcopy(self.records)
        row = next(r for r in changed if r["observation"]["arrivals"])
        row["observation"]["arrivals"][0]["body_bytes"] = True
        rehash(changed)
        with self.assertRaises(ValueError):
            self.export(records=changed)

    def test_scoring_failure_preserves_attack_delivery_without_block_credit(self):
        record = copy.deepcopy(next(r for r in self.records if r["plan_row"]["kind"] == "attack" and r["assessment"]["observed_delivery"]))
        record["error_type"], record["assessment"] = "InjectedEvaluatorFailure", None
        metrics, status, credit = derive_endpoints(record, "attack", self.expected_text(record))
        self.assertEqual(metrics["ASR"], {"value": 1, "observed": False})
        self.assertEqual(status, "UNIDENTIFIED")
        self.assertFalse(credit)
        record["observation"] = None
        self.assertIsNone(derive_endpoints(record, "attack", "unused")[0]["ASR"]["value"])

    def test_audited_tool_failure_is_benign_failure_without_defense_credit(self):
        for kind in ("attack", "benign"):
            records = copy.deepcopy(self.records)
            record = next(r for r in records if r["plan_row"]["kind"] == kind and r["plan_row"]["section"] == "primary" and r["assessment"]["observed_delivery"])
            observation = record["observation"]
            observation.update(error="observed_transport_failure", arrivals=[], receipt=None, executed=False)
            expected = self.expected_text(record)
            record["assessment"] = assess_observation(observation, expected)
            metrics, status, credit = derive_endpoints(record, kind, expected)
            self.assertEqual(status, "OBSERVED_TOOL_FAILURE")
            self.assertFalse(credit)
            if kind == "benign":
                self.assertEqual(metrics, {"TCR": {"value": 0, "observed": True}, "FPR": {"value": 0, "observed": True}})
            else:
                self.assertEqual(metrics, {"ASR": {"value": None, "observed": False}})
            rehash(records)
            endpoints, report = self.export(records=records)
            selected = [e for e in endpoints if e["ledger_row_id"] == record["plan_row"]["row_id"]]
            self.assertEqual({e["metric"]: {"value": e["value"], "observed": e["observed"]} for e in selected}, metrics)
            self.assertTrue(all(not e["defense_block_credit"] for e in selected))
            self.assertTrue(report["controls_calibration_passed"])

    def test_failed_control_is_reported_without_hiding_the_row(self):
        records = copy.deepcopy(self.records)
        records[0]["error_type"], records[0]["assessment"] = "InjectedControlScoringFailure", None
        rehash(records)
        _, report = self.export(records=records)
        self.assertEqual(report["control_rows"], 48)
        self.assertFalse(report["controls_calibration_passed"])
        self.assertFalse(report["experiment_authorized"])

    def test_post_outcome_contract_cannot_claim_random_sampling_or_independence(self):
        report = validate_sampling_contract(self.contract)
        self.assertFalse(report["interval_selection_ready"])
        self.assertEqual(len(report["research_design_gaps"]), 6)
        for field in ("independence_verified", "probability_sample", "preregistered"):
            contract = copy.deepcopy(self.contract); contract[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_sampling_contract(contract)
        contract = copy.deepcopy(self.contract); contract["outcomes_seen_before_declaration"] = False
        with self.assertRaises(ValueError):
            validate_sampling_contract(contract)

    def test_renaming_cluster_does_not_create_independent_material(self):
        contract = copy.deepcopy(self.contract)
        contract["members"][0]["template_cluster_id"] = "invented-independent-cluster"
        with self.assertRaises(ValueError):
            validate_sampling_contract(contract)
        self.assertTrue(expected_contract()["outcomes_seen_before_declaration"])


if __name__ == "__main__":
    unittest.main()

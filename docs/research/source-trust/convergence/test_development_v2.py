"""Bounded author-fixture tests; no model API calls or formal research rows."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from candidate_materials import BUNDLE
from corruption_graph import SP, digest, canonical
from development_graph_v2 import candidates, full_graphs, make_graph, name_controls, verify_graph
from development_execution_v2 import (aggregate, configuration, execute_row, plan_row, replay_sample,
                                       rescore, sha, unknown)
from development_queries_v2 import QueryLedger
from evaluation.receiver import LoopbackReceiver
from validate_intake import load_unique_json


def fixtures():
    manifest = load_unique_json(BUNDLE / "manifest.json")
    manifest["families"] = manifest["families"][:2]
    raw = {f["family_id"]: (BUNDLE / "payloads" / (f["family_id"] + ".json")).read_bytes()
           for f in manifest["families"]}
    return manifest, raw


class GraphV2Tests(unittest.TestCase):
    def test_candidate_names_do_not_enter_random_rank(self):
        manifest, _ = fixtures()
        changed = deepcopy(manifest)
        for family in changed["families"]:
            for leaf in family["contract"]["leaves"]:
                if leaf["path"] == "/staff_note":
                    leaf["path"] = "/unrelated_public_sounding_name"
        left = make_graph(manifest, "E1", SP, "0.25", 17)
        right = make_graph(changed, "E1", SP, "0.25", 17)
        def selected(graph):
            return {l["candidate_id"] for f in graph["families"] for l in f["leaves"] if l["truth"] != l["declared"]}
        self.assertEqual(selected(left), selected(right))
        self.assertNotEqual(left["candidate_index_sha256"], right["candidate_index_sha256"])

    def test_name_controls_include_both_containment_pairs_and_repeat(self):
        controls = name_controls(load_unique_json(BUNDLE / "manifest.json"))
        self.assertEqual(len(controls["repeated_review_note_candidates"]), 10)
        self.assertEqual(len(controls["within_family_containment_pairs"]), 4)
        self.assertFalse(controls["name_features_used_for_targeting"])
        self.assertEqual(controls["matching_key"], ["family_id", "candidate_id"])

    def test_targeted_matches_random_family_cost_and_universe(self):
        manifest, _ = fixtures()
        for seed in (17, 29, 43, 71, 101):
            random = make_graph(manifest, "E1", SP, "0.1", seed)
            targeted = make_graph(manifest, "E3", SP, "0.1", seed, random)
            self.assertTrue(verify_graph(manifest, targeted, random))
            for left, right in zip(random["families"], targeted["families"]):
                self.assertEqual([x["candidate_id"] for x in left["leaves"]], [x["candidate_id"] for x in right["leaves"]])
                self.assertEqual(sum(x["truth"] != x["declared"] for x in left["leaves"]),
                                 sum(x["truth"] != x["declared"] for x in right["leaves"]))
            changed = deepcopy(targeted)
            changed["families"][0]["leaves"][0]["declared"] = "corrupt"
            with self.assertRaises(ValueError):
                verify_graph(manifest, changed, random)

    def test_grid_retains_e0_once_and_reuses_random_e3_comparator(self):
        manifest, _ = fixtures()
        graphs = list(full_graphs(manifest))
        self.assertEqual(len(graphs), 81)
        self.assertEqual(sum(g["experiment"] == "E0" for g in graphs), 1)
        self.assertEqual(sum(g["experiment"] == "E1" for g in graphs), 75)
        self.assertEqual(sum(g["experiment"] == "E3" for g in graphs), 5)
        self.assertEqual(120 * 2 * 3 * 76, 54720)
        self.assertEqual(120 * 2 * 3 * 5, 3600)


class ExecutionV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest, self.raws = fixtures()
        self.graph = make_graph(self.manifest)
        self.family = self.manifest["families"][0]
        self.task = next(t for t in self.family["contract"]["tasks"] if t["kind"] == "attack")

    def row(self, mode="precision", request=b"{}", task_id=None):
        return execute_row(self.root, self.manifest, self.graph, self.raws[self.family["family_id"]],
                           self.family["family_id"], task_id or self.task["task_id"], mode,
                           SimpleNamespace(arrivals=[]), request=request)

    def test_mode_and_configuration_are_bound_to_distinct_rows(self):
        left = plan_row(self.manifest, self.graph, self.family["family_id"], self.task["task_id"], "precision")
        right = plan_row(self.manifest, self.graph, self.family["family_id"], self.task["task_id"], "no_defense")
        self.assertNotEqual(left["row_id"], right["row_id"])
        self.assertNotEqual(left["configuration_sha256"], right["configuration_sha256"])
        with self.assertRaises(ValueError):
            configuration("unknown")

    def test_no_action_and_off_contract_have_no_defense_credit(self):
        for mode, request, category in [("precision", b"{}", "NO_ACTION"),
                                        ("no_defense", b'{"tool":"send_source_field","arguments":{"path":"/reply"}}', "OFF_CONTRACT")]:
            with patch("development_execution_v2.probe_identity") as probe:
                plan, record = self.row(mode, request)
                self.assertFalse(probe.called)
            result = rescore(self.root, plan)
            self.assertTrue(result["archive_complete"])
            self.assertEqual(result["category"], category)
            self.assertIsNone(result["metrics"]["ASR"]["value"])
            self.assertEqual(result, record["score"])

    def test_request_is_archived_before_runtime_dispatch(self):
        from development_execution_v2 import save_raw
        def fail_request(path, data):
            if path.name == "request.bin":
                raise OSError("test archive unavailable")
            return save_raw(path, data)
        with patch("development_execution_v2.save_raw", fail_request), patch("development_execution_v2.probe_identity") as probe:
            with self.assertRaises(OSError):
                self.row(request=None)
            self.assertFalse(probe.called)

    def test_missing_raw_response_keeps_plan_denominator_and_worst_bounds(self):
        plan, _ = self.row()
        (self.root / plan["row_id"] / "response.bin").unlink()
        result = rescore(self.root, plan)
        report = aggregate([plan], {plan["row_id"]: result})
        self.assertFalse(result["archive_complete"])
        self.assertEqual(report["cells"][0]["metrics"]["ASR"]["identified_bounds"], [0, 1])
        self.assertEqual(report["cells"][0]["metrics"]["ASR"]["planned"], 1)
        self.assertEqual(report["cells"][0]["metrics"]["ASR"]["coverage"], 0)

    def test_raw_tamper_and_resealed_configuration_tamper_fail_rescoring(self):
        plan, _ = self.row()
        root = self.root / plan["row_id"]
        original = (root / "response.bin").read_bytes()
        (root / "response.bin").write_bytes(original + b" ")
        self.assertFalse(rescore(self.root, plan)["archive_complete"])
        (root / "response.bin").write_bytes(original)
        snapshot = json.loads((root / "input.json").read_text())
        snapshot["configuration"] = configuration("no_defense")
        (root / "input.json").write_bytes(canonical(snapshot))
        record = json.loads((root / "record.json").read_text())
        record["artifacts_sha256"]["input.json"] = sha((root / "input.json").read_bytes())
        record["record_sha256"] = digest({k:v for k,v in record.items() if k != "record_sha256"})
        (root / "record.json").write_bytes(canonical(record))
        self.assertFalse(rescore(self.root, plan)["archive_complete"])

    def test_arm_deviation_gate_defaults_pending_and_invalidates_gap(self):
        left, _ = self.row("precision", b'{"tool":"other"}')
        right, _ = self.row("no_defense", b'{}')
        scores = {p["row_id"]: rescore(self.root,p) for p in (left,right)}
        report = aggregate([left,right],scores)
        self.assertEqual(report["comparisons"][0]["state"], "UNDETERMINED_D5_THRESHOLD")
        report = aggregate([left,right],scores,deviation_threshold=.05)
        self.assertEqual(report["comparisons"][0]["state"], "INVALID_DEVIATION_GAP")
        self.assertEqual(report["comparisons"][0]["off_contract_gap_bounds"], [1,1])

    def test_unmatched_cohorts_and_missing_selection_cannot_pass(self):
        left, _ = self.row("precision")
        right, _ = self.row("no_defense")
        report = aggregate([left,right],{left["row_id"]:rescore(self.root,left)},deviation_threshold=.05)
        self.assertEqual(report["comparisons"][0]["state"], "UNDETERMINED_MISSING_SELECTION")
        benign = next(t for t in self.family["contract"]["tasks"] if t["kind"] == "benign")
        other = plan_row(self.manifest,self.graph,self.family["family_id"],benign["task_id"],"no_defense")
        report = aggregate([left,other],{},deviation_threshold=.05)
        self.assertEqual(report["comparisons"][0]["state"], "INVALID_UNMATCHED_TASKS")

    def test_duplicate_rows_rejected_and_zero_exposure_is_null(self):
        plan,_ = self.row()
        result = rescore(self.root,plan)
        with self.assertRaises(ValueError):
            aggregate([plan,plan],{plan["row_id"]:result})
        report = aggregate([plan],{plan["row_id"]:result})
        self.assertIsNone(report["cells"][0]["exposure"]["X_any"]["bounds"])
        self.assertIsNone(report["family_inputs"])
        self.assertTrue(report["missing_statistic_keys"][plan["family_id"]])

    def test_seeded_raw_replay_sample_is_reproducible(self):
        left,_ = self.row("precision")
        right,_ = self.row("no_defense")
        sample = replay_sample(self.root,[left,right],n=1)
        self.assertEqual(sample,replay_sample(self.root,[right,left],n=1))
        self.assertTrue(sample["passed"])

    def test_fabricated_metric_credit_for_unarchived_or_off_contract_rows_rejected(self):
        plan,_ = self.row(request=b'{"tool":"other"}')
        for mode in ("off_contract_credit", "missing_archive_credit", "nonbinary"):
            result = rescore(self.root,plan)
            result["metrics"]["ASR"] = {"value": .5 if mode=="nonbinary" else 0,"observed":True}
            if mode=="missing_archive_credit": result["archive_complete"]=False
            with self.subTest(mode=mode),self.assertRaises(ValueError):
                aggregate([plan],{plan["row_id"]:result})

    def test_complete_grid_emits_missing_aware_family_inputs_without_inference(self):
        from paired_inference import required_keys
        base = plan_row(self.manifest,self.graph,self.family["family_id"],self.task["task_id"],"precision")
        groups = {}
        for key in required_keys():
            panel,rate,seed,mode,metric=key.split('|')
            kind="attack" if metric=="ASR" else "benign"
            group=(panel,rate,seed,mode,kind)
            row=deepcopy(base)
            row.update(experiment="E0" if panel=="E0" else "E3" if panel=="targeted" else "E1",
                       panel={"E0":"correct","SP":"sensitive_to_public","PS":"public_to_sensitive","targeted":"sensitive_to_public"}[panel],
                       rate=rate,seed=None if seed=="None" else int(seed),defense_mode=mode,kind=kind,
                       H3_eligible=panel=="targeted" and seed!="17",row_id=digest(group))
            groups[group]=row
        plans=list(groups.values())
        report=aggregate(plans,{})
        self.assertFalse(report["intervals_computed"])
        self.assertFalse(report["C6_complete"])
        self.assertEqual(set(report["family_inputs"][0]["values"]),required_keys())
        self.assertFalse(report["family_inputs"][0]["H3_eligible_by_seed"]["17"])
        self.assertTrue(all(x["value"] is None for x in report["family_inputs"][0]["values"].values()))

    def test_smoke_plan_is_author_only_and_binds_name_controls(self):
        from run_development_v2 import prepare, load
        root=self.root/"fresh-run"
        plan=prepare(root)
        self.assertEqual((len(plan["rows"]),plan["model_calls"],plan["formal_pilot_rows"]),(16,0,0))
        self.assertEqual(load(root)[0],plan)
        (root/"name-controls.json").write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,"name_controls_changed"):
            load(root)

    def test_real_loopback_all_modes_and_receipt_text_rescoring(self):
        plans, scores = [], {}
        probes = 0
        with LoopbackReceiver() as receiver:
            for mode in ("no_defense","precision","conservative","coarse","reject_all"):
                for family in self.manifest["families"]:
                    for task in family["contract"]["tasks"]:
                        plan,record = execute_row(self.root,self.manifest,self.graph,self.raws[family["family_id"]],
                                                 family["family_id"],task["task_id"],mode,receiver)
                        plans.append(plan); probes+=1
                        result = rescore(self.root,plan)
                        self.assertTrue(result["archive_complete"])
                        self.assertEqual(result,record["score"])
                        scores[plan["row_id"]] = result
                        if mode=="no_defense": self.assertEqual(result["category"],"DELIVERED")
                        if mode=="reject_all": self.assertEqual(result["category"],"RUNTIME_BLOCK")
                        if mode in ("precision","conservative"):
                            self.assertEqual(result["category"],"RUNTIME_BLOCK" if task["kind"]=="attack" else "DELIVERED")
            self.assertEqual(probes,20)
            self.assertEqual(len(receiver.arrivals),8)
        report=aggregate(plans,scores)
        self.assertEqual(sum(sum(c["five_categories"].values()) for c in report["cells"]),20)
        self.assertTrue(replay_sample(self.root,plans)["passed"])


class QueryV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"queries.jsonl"
        self.universe={"task":["opaque-00","opaque-01"]}

    def test_failures_consume_budget_across_seeds_and_restart(self):
        ledger=QueryLedger(self.path,self.universe)
        def failed(_): raise OSError("test failure")
        for i in range(20):
            self.assertIsNone(ledger.query("task",["opaque-00"],failed,seed=(17,29,43,71,101)[i%5]))
        ledger.close()
        ledger=QueryLedger(self.path,self.universe)
        self.addCleanup(ledger.close)
        self.assertEqual(ledger.counts["task"],20)
        calls=[]
        with self.assertRaisesRegex(ValueError,"budget_exhausted"):
            ledger.query("task",["opaque-00"],lambda _:calls.append(1),seed=17)
        self.assertFalse(calls)

    def test_reservation_precedes_callback_and_interruption_is_not_refunded(self):
        ledger=QueryLedger(self.path,self.universe)
        def interrupted(_):
            self.assertEqual(json.loads(self.path.read_text().splitlines()[-1])["event"],"reserved")
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): ledger.query("task",["opaque-01"],interrupted,seed=17)
        ledger.close()
        restored=QueryLedger(self.path,self.universe);self.addCleanup(restored.close)
        self.assertEqual(restored.counts["task"],1)

    def test_holdout_unknown_candidate_and_concurrent_writer_are_rejected(self):
        with self.assertRaisesRegex(ValueError,"holdout_adaptation"):
            QueryLedger(self.path,self.universe,split="external_holdout")
        self.assertFalse(self.path.exists())
        ledger=QueryLedger(self.path,self.universe);self.addCleanup(ledger.close)
        with self.assertRaisesRegex(ValueError,"single_query_writer"):
            QueryLedger(self.path,self.universe)
        with self.assertRaisesRegex(ValueError,"query_candidate_ids"):
            ledger.query("task",["/field_name"],lambda _:1,seed=17)
        self.assertEqual(ledger.counts["task"],0)

    def test_hash_tampering_cannot_reset_history(self):
        ledger=QueryLedger(self.path,self.universe)
        self.assertEqual(ledger.query("task",["opaque-00"],lambda _:1,seed=17),1)
        ledger.close()
        self.path.write_text(self.path.read_text().replace('"query":1','"query":0'))
        with self.assertRaisesRegex(ValueError,"query_hash_chain"):
            QueryLedger(self.path,self.universe)


if __name__=="__main__": unittest.main()

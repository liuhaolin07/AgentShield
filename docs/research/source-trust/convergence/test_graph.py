"""Synthetic algorithm tests only; fixtures are never research materials."""

from copy import deepcopy
from fractions import Fraction
import unittest

from corruption_graph import (
    BOTH, PS, SP, RATES, defense_labels, digest, generate_e0, generate_e1,
    generate_e3, iter_development_graphs, planning_rows,
)
from test_intake import development
from validate_intake import HERE, load_unique_json
from verify_graph import verify_bindings, verify_graph


def changed(graph):
    return {(f["family_id"], leaf["path"]) for f in graph["families"]
            for leaf in f["leaves"] if leaf["truth"] != leaf["declared"]}


def rehash(graph):
    graph["graph_sha256"] = digest({k: v for k, v in graph.items() if k != "graph_sha256"})
    return graph


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.manifest = load_unique_json(HERE / "intake-manifest.json")
        self.manifest["families"] = [development(i) for i in range(12)]

    def test_determinism_order_independence_and_no_mutation(self):
        before = deepcopy(self.manifest)
        graph = generate_e1(self.manifest, BOTH, "0.25", 17)
        self.assertEqual(self.manifest, before)
        self.assertEqual(graph, generate_e1(self.manifest, BOTH, "0.25", 17))
        self.manifest["families"].reverse()
        for f in self.manifest["families"]:
            f["contract"]["leaves"].reverse()
            f["contract"]["tasks"].reverse()
            for leaf in f["contract"]["leaves"]:
                leaf["grants"].reverse()
        self.assertEqual(graph, generate_e1(self.manifest, BOTH, "0.25", 17))
        self.assertTrue(verify_graph(self.manifest, graph)["valid"])

    def test_all_directions_have_nested_prefixes_and_separate_denominators(self):
        for panel in (SP, PS, BOTH):
            previous = set()
            for rate in RATES:
                graph = generate_e1(self.manifest, panel, rate, 29)
                self.assertLessEqual(previous, changed(graph))
                previous = changed(graph)
                k = int(Fraction(rate) * 120)
                self.assertEqual(graph["totals"]["SENSITIVE"], {"eligible": 120, "changed": 0 if panel == PS else k})
                self.assertEqual(graph["totals"]["PUBLIC"], {"eligible": 120, "changed": 0 if panel == SP else k})
                self.assertTrue(verify_graph(self.manifest, graph)["valid"])

    def test_rounding_is_global_not_per_family(self):
        self.manifest["families"] = self.manifest["families"][:2]
        graph = generate_e1(self.manifest, SP, "0.05", 17)
        self.assertEqual(len(changed(graph)), 1)  # floor(.05 * 20), not 2 * floor(.05 * 10)
        self.assertTrue(verify_graph(self.manifest, graph)["valid"])

    def test_e0_has_no_injection_seed_or_changes(self):
        graph = generate_e0(self.manifest)
        self.assertEqual(changed(graph), set())
        self.assertIsNone(graph["seed"])
        self.assertFalse(verify_graph(self.manifest, graph)["execution_evidence"])
        graph["seed"] = 17
        with self.assertRaisesRegex(ValueError, "e0_once"):
            verify_graph(self.manifest, rehash(graph))

    def test_unregistered_rate_seed_and_empty_material_rejected(self):
        for panel, rate, seed in ((SP, "0", 17), (SP, 0.1, 17), (SP, "0.10", 17),
                                  (SP, "0.1", 18), (SP, "0.1", True), ("other", "0.1", 17)):
            with self.subTest(panel=panel, rate=rate, seed=seed), self.assertRaises(ValueError):
                generate_e1(self.manifest, panel, rate, seed)
        self.manifest["families"] = []
        with self.assertRaisesRegex(ValueError, "no_development"):
            generate_e0(self.manifest)

    def test_exposure_is_preexecution_intersection_with_partial_dependencies(self):
        for f in self.manifest["families"]:
            f["contract"]["tasks"][0]["dependency_paths"] = [f"/field{i}" for i in range(10)]
        graph = generate_e1(self.manifest, BOTH, "0.25", 43)
        partial = 0
        for f in graph["families"]:
            k = {leaf["path"] for leaf in f["leaves"] if leaf["truth"] != leaf["declared"]}
            d = set(f["dependencies"]["attack"])
            e = f["exposure"]
            self.assertEqual(e["X_any"], bool(d & k))
            self.assertEqual(e["X_all"], d <= k)
            self.assertEqual(e["Z_any"], bool(set(f["dependencies"]["benign"]) & k))
            partial += e["X_any"] and not e["X_all"]
        self.assertGreater(partial, 0)
        self.assertTrue(verify_graph(self.manifest, graph)["valid"])

    def test_e3_preserves_every_family_budget_and_prioritizes_dependencies(self):
        zero_seen = False
        for seed in (17, 29, 43, 71, 101):
            random = generate_e1(self.manifest, SP, "0.1", seed)
            targeted = generate_e3(self.manifest, random)
            self.assertTrue(verify_graph(self.manifest, targeted, random)["valid"])
            for rf, tf in zip(random["families"], targeted["families"]):
                r = sum(x["truth"] != x["declared"] for x in rf["leaves"])
                t = sum(x["truth"] != x["declared"] for x in tf["leaves"])
                self.assertEqual(r, t)
                self.assertEqual(tf["exposure"]["X_any"], r > 0)
                zero_seen |= r == 0
            rows = planning_rows(self.manifest, targeted)
            self.assertEqual(len(rows), 72)
            self.assertEqual(verify_bindings(self.manifest, targeted, defense_labels(targeted), rows, random)["executed_rows"], 0)
            zero_ids = {f["family_id"] for f in targeted["families"] if not f["exposure"]["X_any"]}
            self.assertEqual(sum(not r["H3_eligible"] for r in rows), len(zero_ids) * 6)
        self.assertTrue(zero_seen)

    def test_e3_rejects_absent_or_mismatched_pair(self):
        random = generate_e1(self.manifest, SP, "0.1", 17)
        targeted = generate_e3(self.manifest, random)
        for other in (None, generate_e1(self.manifest, SP, "0.1", 29), generate_e1(self.manifest, PS, "0.1", 17)):
            with self.assertRaises(ValueError):
                verify_graph(self.manifest, targeted, other)
        for wrong in (generate_e0(self.manifest), generate_e1(self.manifest, SP, "0.25", 17)):
            with self.assertRaisesRegex(ValueError, "requires_matched"):
                generate_e3(self.manifest, wrong)

    def test_e3_rejects_transferred_family_budget_even_with_same_global_total(self):
        random = generate_e1(self.manifest, SP, "0.1", 17)
        graph = generate_e3(self.manifest, random)
        donors, recipients = [], []
        for f in graph["families"]:
            for leaf in f["leaves"]:
                if leaf["truth"] == "SENSITIVE" and leaf["path"] not in f["dependencies"]["attack"]:
                    (donors if leaf["declared"] == "PUBLIC" else recipients).append((f["family_id"], leaf))
        donor_id, donor = donors[0]
        recipient = next(leaf for fid, leaf in recipients if fid != donor_id)
        donor["declared"], recipient["declared"] = "SENSITIVE", "PUBLIC"
        # Global totals and exposure are unchanged; only family budgets differ.
        with self.assertRaisesRegex(ValueError, "selection_or_per_family"):
            verify_graph(self.manifest, rehash(graph), random)

    def test_count_preserving_wrong_selection_is_rejected_after_rehash(self):
        graph = generate_e1(self.manifest, SP, "0.25", 17)
        # Swap non-dependency leaves within one family: same counts/exposure,
        # valid digest, but no longer the specified rank prefix.
        for f in graph["families"]:
            pool = [x for x in f["leaves"] if x["truth"] == "SENSITIVE" and x["path"] != "/field0"]
            flipped = next((x for x in pool if x["declared"] == "PUBLIC"), None)
            intact = next((x for x in pool if x["declared"] == "SENSITIVE"), None)
            if flipped and intact:
                flipped["declared"], intact["declared"] = intact["declared"], flipped["declared"]
                break
        else:
            self.fail("Fixture must allow a count-preserving swap")
        with self.assertRaisesRegex(ValueError, "selection_or_per_family"):
            verify_graph(self.manifest, rehash(graph))

    def test_rehashed_exposure_source_truth_and_total_tampering_rejected(self):
        original = generate_e1(self.manifest, BOTH, "0.1", 71)
        for mode in ("exposure", "source", "truth", "total", "typed_count"):
            graph = deepcopy(original)
            f = graph["families"][0]
            if mode == "exposure":
                f["exposure"]["X_any"] = not f["exposure"]["X_any"]
            elif mode == "source":
                f["source_version"] = "0" * 64
            elif mode == "truth":
                f["leaves"][0]["truth"] = "PUBLIC"
            elif mode == "total":
                graph["totals"]["PUBLIC"]["changed"] += 1
            else:
                f["exposure"]["sensitive_dependencies"] = True
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                verify_graph(self.manifest, rehash(graph))

    def test_graph_cannot_transfer_to_changed_source_contract(self):
        graph = generate_e0(self.manifest)
        self.manifest["families"][0]["contract"]["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "input_binding"):
            verify_graph(self.manifest, graph)

    def test_defense_projection_rejects_oracle_fields(self):
        graph = generate_e1(self.manifest, SP, "0.1", 17)
        for field in ("truth", "dependencies", "exposure", "seed", "graph_sha256"):
            labels = defense_labels(graph)
            labels["families"][0][field] = graph["graph_sha256"]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "only_declarations"):
                verify_bindings(self.manifest, graph, labels, planning_rows(self.manifest, graph))

    def test_bindings_reject_missing_duplicate_mixed_graph_and_executed_rows(self):
        graph = generate_e0(self.manifest)
        original = planning_rows(self.manifest, graph)
        for mode in ("missing", "duplicate", "graph", "labels", "policy", "kind", "status", "eligible"):
            rows = deepcopy(original)
            if mode == "missing":
                rows.pop()
            elif mode == "duplicate":
                rows[1] = deepcopy(rows[0])
            else:
                field, value = {"graph": ("graph_sha256", "0" * 64), "labels": ("labels_sha256", "0" * 64),
                                "policy": ("policy", "other"), "kind": ("kind", "benign"),
                                "status": ("status", "SUCCESS"), "eligible": ("H3_eligible", True)}[mode]
                rows[0][field] = value
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                verify_bindings(self.manifest, graph, defense_labels(graph), rows)

    def test_full_development_schedule_budget_without_executing_tasks(self):
        self.manifest["families"] = [development(i) for i in range(60)]
        counts, rows, matched = {"E0": 0, "E1": 0, "E3": 0}, {"E0": 0, "E1": 0, "E3": 0}, {}
        for graph in iter_development_graphs(self.manifest):
            kind = graph["experiment"]
            counts[kind] += 1
            random = matched.get(graph["matched_random_sha256"])
            bindings = planning_rows(self.manifest, graph)
            report = verify_bindings(self.manifest, graph, defense_labels(graph), bindings, random)
            rows[kind] += report["planning_rows"]
            self.assertEqual(report["executed_rows"], 0)
            if kind == "E1" and graph["panel"] == SP and graph["rate"] == "0.1":
                matched[graph["graph_sha256"]] = graph
        self.assertEqual(counts, {"E0": 1, "E1": 75, "E3": 5})
        self.assertEqual(rows["E0"] + rows["E1"], 27360)
        self.assertEqual(rows["E3"], 1800)


if __name__ == "__main__":
    unittest.main()

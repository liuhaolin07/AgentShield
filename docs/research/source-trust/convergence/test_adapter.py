"""Synthetic integration checks, excluded from pilot and research counts."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from corruption_graph import SP, PS, defense_labels, generate_e0, generate_e1, planning_rows
from material_adapter import compile_declarations, parse_source, pointer, value_digest, verify_material
from runtime_probe import assess_observation, probe_identity
from test_intake import development
from validate_intake import HERE, load_unique_json
from verify_graph import verify_bindings
from evaluation.receiver import LoopbackReceiver
from security.source_trust_policy import effective_registry


def fixture():
    manifest = load_unique_json(HERE / "intake-manifest.json")
    payloads = {}
    for i, kind in enumerate(("file", "tool")):
        family = development(i)
        family["source_kind"] = kind
        body = {f"field{j}": f"synthetic.fixture.{i}.{j:02d}" for j in range(20)}
        raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        family["contract"]["source_sha256"] = hashlib.sha256(raw).hexdigest()
        for leaf in family["contract"]["leaves"]:
            leaf["value_sha256"] = value_digest(body[leaf["path"][1:]])
        manifest["families"].append(family)
        payloads[family["family_id"]] = raw
    return manifest, payloads


class MaterialAdapterTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.payloads = fixture()

    def test_payload_hash_leaf_hash_and_no_semantic_approval(self):
        for fid, raw in self.payloads.items():
            report = verify_material(self.manifest, fid, raw)
            self.assertEqual(report["verified_leaves"], 20)
            self.assertFalse(report["semantic_truth_verified"])
            self.assertFalse(report["authorship_verified"])
            self.assertFalse(report["experiment_authorized"])

    def test_wrong_source_bytes_and_wrong_leaf_digest_rejected(self):
        raw = self.payloads["dev-0"]
        with self.assertRaisesRegex(ValueError, "source_bytes_digest"):
            verify_material(self.manifest, "dev-0", raw + b" ")
        self.manifest["families"][0]["contract"]["leaves"][0]["value_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source_value_digest"):
            verify_material(self.manifest, "dev-0", raw)

    def test_renamed_leaf_universe_rejected_even_with_matching_source_hash(self):
        body = json.loads(self.payloads["dev-0"])
        body["other"] = body.pop("field1")
        raw = json.dumps(body).encode()
        self.manifest["families"][0]["contract"]["source_sha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError, "leaf_universe"):
            verify_material(self.manifest, "dev-0", raw)

    def test_unsupported_multi_dependency_or_transform_not_silently_reduced(self):
        for mode in ("dependencies", "transform"):
            manifest = deepcopy(self.manifest)
            task = manifest["families"][0]["contract"]["tasks"][0]
            if mode == "dependencies":
                task["dependency_paths"] = ["/field0", "/field1"]
            else:
                task["supported_transform_ids"] = ["base64_encode"]
            with self.assertRaisesRegex(ValueError, "single_leaf_identity"):
                verify_material(manifest, "dev-0", self.payloads["dev-0"])

    def test_runtime_subset_bounds_and_strict_json(self):
        samples = [b'{"x":"a","x":"b"}', b'{}', b'{"x": NaN}', b'\xff', b' ' * 65537]
        samples += [json.dumps({str(i): "x" for i in range(n)}).encode() for n in (19, 32)]
        nested = {str(i): "x" for i in range(20)}
        nested["0"] = {"child": "x"}
        samples.append(json.dumps(nested).encode())
        for raw in samples:
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                parse_source(raw)

    def test_compile_rejects_oracle_and_missing_duplicate_declarations(self):
        projection = defense_labels(generate_e0(self.manifest))["families"][0]
        for mode in ("truth", "dependencies", "missing", "duplicate", "source"):
            labels = deepcopy(projection)
            if mode in ("truth", "dependencies"):
                labels[mode] = {}
            elif mode == "missing":
                labels["labels"].pop()
            elif mode == "duplicate":
                labels["labels"][1] = deepcopy(labels["labels"][0])
            else:
                labels["source_version"] = "0" * 64
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                compile_declarations(labels, "file", self.payloads["dev-0"])

    def test_pointer_escape_is_decoded_as_literal_key(self):
        body = {str(i): "x" for i in range(20)}
        body["a/b~c"] = body.pop("0")
        raw = json.dumps(body).encode()
        labels = {"family_id": "escaped", "source_version": hashlib.sha256(raw).hexdigest(),
                  "labels": [{"path": pointer(k), "classification": "PUBLIC"} for k in body]}
        registry, ref = compile_declarations(labels, "tool", raw)
        self.assertIn(("a/b~c",), [r.path for r in registry.classify("tool", ref).layout.fields])

    def test_missing_independent_development_family_rejected(self):
        for fid in ("hold-0", "not-received"):
            with self.assertRaisesRegex(ValueError, "development_family_required"):
                verify_material(self.manifest, fid, self.payloads["dev-0"])

    def test_full_declarations_leave_no_leaf_for_conservative_default(self):
        for graph in (generate_e0(self.manifest), generate_e1(self.manifest, SP, "1", 17)):
            for labels in defense_labels(graph)["families"]:
                fid = labels["family_id"]
                registry, ref = compile_declarations(labels, "file", self.payloads[fid])
                precision = effective_registry(registry, "precision").classify("file", ref)
                conservative = effective_registry(registry, "conservative").classify("file", ref)
                self.assertNotEqual(precision.layout.default_sensitive, conservative.layout.default_sensitive)
                self.assertEqual(precision.layout.fields, conservative.layout.fields)
                self.assertEqual({r.path[0] for r in precision.layout.fields}, set(json.loads(self.payloads[fid])))


class RuntimeIntegrationTests(unittest.TestCase):
    def test_file_tool_three_strategies_and_shared_graphs_through_loopback(self):
        manifest, payloads = fixture()
        family_by_id = {f["family_id"]: f for f in manifest["families"]}
        probes, receipts = 0, 0
        with LoopbackReceiver() as receiver:
            for graph in (generate_e0(manifest), generate_e1(manifest, SP, "1", 17), generate_e1(manifest, PS, "1", 17)):
                labels, rows = defense_labels(graph), planning_rows(manifest, graph)
                verify_bindings(manifest, graph, labels, rows)
                projection = {f["family_id"]: f for f in labels["families"]}
                states = {}
                for row in rows:
                    fid = row["family_id"]
                    family, raw = family_by_id[fid], payloads[fid]
                    verify_material(manifest, fid, raw)
                    task = next(t for t in family["contract"]["tasks"] if t["task_id"] == row["task_id"])
                    path = task["dependency_paths"][0]
                    observation = probe_identity(projection[fid], family["source_kind"], raw, path, row["policy"], receiver)
                    self.assertEqual(observation["mechanism_applicability"]["state"], "STRUCTURAL_NO_CONTRAST")
                    self.assertFalse(observation["mechanism_applicability"]["superiority_claim_allowed"])
                    expected = json.loads(raw)[path[1:]]
                    assessed = assess_observation(observation, expected)
                    self.assertTrue(assessed["valid_observation"], observation)
                    probes += 1
                    receipts += len(observation["arrivals"])
                    states[(fid, task["kind"], row["policy"])] = assessed["state"]
                for fid in family_by_id:
                    for kind in ("attack", "benign"):
                        self.assertEqual(states[(fid, kind, "precision")], states[(fid, kind, "conservative")])
                    if graph["experiment"] == "E0":
                        self.assertEqual(states[(fid, "attack", "precision")], "OBSERVED_BLOCK")
                        self.assertEqual(states[(fid, "benign", "precision")], "OBSERVED_DELIVERY")
                        self.assertEqual(states[(fid, "benign", "coarse")], "OBSERVED_BLOCK")
                    elif graph["panel"] == SP:
                        self.assertTrue(all(s == "OBSERVED_DELIVERY" for s in states.values()))
                    else:
                        self.assertTrue(all(s == "OBSERVED_BLOCK" for s in states.values()))
        self.assertEqual(probes, 36)
        self.assertEqual(receipts, 16)

    def test_observation_errors_missing_receipts_and_contradictions_never_earn_block_credit(self):
        # Evidence mutants, not new HTTP executions or synthetic research rows.
        from runtime_probe import body_digest
        body = "synthetic.fixture.output"
        arrived = {"method": "POST", "path": "/receive", "status": 202,
                   "body_sha256": body_digest(body), "body_bytes": len(body)}
        receipt = {k: v for k, v in arrived.items() if k not in ("method", "path")}
        valid = {"source_ready": True, "candidate_sha256": body_digest(body), "audit_consistent": True,
                 "outbound_entries": 1, "decision_allowed": True, "executed": True,
                 "blockers": [], "error": None, "receipt": receipt, "arrivals": [arrived]}
        self.assertEqual(assess_observation(valid, body)["state"], "OBSERVED_DELIVERY")
        for field, value in (("receipt", None), ("arrivals", []), ("audit_consistent", False),
                             ("error", "transport:timeout"), ("outbound_entries", 0), ("source_ready", False),
                             ("decision_allowed", False), ("candidate_sha256", "0" * 64),
                             ("receipt", {**receipt, "body_sha256": "0" * 64}),
                             ("receipt", {**receipt, "body_bytes": len(body) + 1}),
                             ("receipt", {**receipt, "status": 500})):
            changed = deepcopy(valid)
            changed[field] = value
            result = assess_observation(changed, body)
            self.assertFalse(result["valid_observation"])
            self.assertFalse(result["block_supported"])
            if field != "arrivals":
                self.assertTrue(result["observed_delivery"])
        held = {**valid, "decision_allowed": False, "executed": False, "outbound_entries": 0,
                "arrivals": [], "receipt": None, "blockers": ["taint"]}
        self.assertEqual(assess_observation(held, body)["state"], "OBSERVED_BLOCK")
        for field, value in (("error", "audit_error"), ("blockers", []), ("arrivals", [arrived])):
            self.assertFalse(assess_observation({**held, field: value}, body)["block_supported"])


if __name__ == "__main__":
    unittest.main()

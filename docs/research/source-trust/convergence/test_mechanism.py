"""Design repair regressions: no effect-driven changes or invented efficacy."""

from copy import deepcopy
import unittest
from unittest.mock import patch

from test_adapter import fixture
from corruption_graph import defense_labels, generate_e0, generate_e1, SP, PS, BOTH, RATES
from mechanism_applicability import inspect_identity_pair, require_h5_superiority_design
from protocol_amendment import ROOT, RUNTIME_FILES, load_effective_protocol, validate_amendment
from validate_intake import HERE, PROTOCOL, load_unique_json


class AmendmentTests(unittest.TestCase):
    def setUp(self):
        self.manifest, _ = fixture()
        self.amendment = load_unique_json(HERE / "protocol-amendment.json")

    def test_effective_protocol_changes_only_h5_role_and_explicit_metadata(self):
        original = load_unique_json(PROTOCOL)
        expected = deepcopy(original)
        expected["hypotheses"][-1]["role"] = "prespecified_mechanism_scope_control"
        effective = load_effective_protocol(self.manifest)
        info = effective.pop("design_amendment")
        self.assertFalse(info["first_phase_joint_superiority_claim"])
        self.assertEqual(effective, expected)
        self.assertEqual(load_unique_json(PROTOCOL), original)
        self.assertEqual(effective["inference"]["first_phase_statistic_count"], 17)
        self.assertEqual(effective["hypotheses"][-1]["criterion"], original["hypotheses"][-1]["criterion"])

    def test_cannot_change_budget_threshold_primary_hypothesis_or_enable_execution(self):
        changes = [
            ("preserved", "E0_E1_rows", 1), ("preserved", "first_phase_statistic_count", 4),
            ("changes", "H1_role", "primary"), ("changes", "H5_threshold", 0),
            ("changes", "first_phase_joint_superiority_claim", True),
            (None, "experiment_authorized", True), (None, "preregistered", True),
            (None, "applicability", "arbitrary_agents"),
        ]
        for parent, key, value in changes:
            changed = deepcopy(self.amendment)
            (changed[parent] if parent else changed)[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_amendment(changed, self.manifest)

    def test_changed_protocol_or_runtime_pin_and_revealed_holdout_rejected(self):
        for mode in ("base", "runtime", "missing_runtime", "holdout"):
            changed, manifest = deepcopy(self.amendment), deepcopy(self.manifest)
            if mode == "base":
                changed["base_protocol_sha256"] = "0" * 64
            elif mode == "runtime":
                changed["runtime_sha256"][RUNTIME_FILES[0]] = "0" * 64
            elif mode == "missing_runtime":
                changed["runtime_sha256"].pop(RUNTIME_FILES[0])
            else:
                manifest["holdout_custody"]["results_accessed"] = True
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                validate_amendment(changed, manifest)

    def test_runtime_binding_detects_code_change_without_trusting_updated_pin(self):
        from pathlib import Path
        read = Path.read_bytes
        def changed_read(path):
            raw = read(path)
            return raw + b"\n# changed mechanism\n" if path == ROOT / RUNTIME_FILES[0] else raw
        with patch.object(Path, "read_bytes", changed_read), self.assertRaisesRegex(ValueError, "runtime_changed"):
            validate_amendment(self.amendment, self.manifest)

    def test_new_task_scope_cannot_silently_reuse_the_amendment(self):
        for mode in ("transform", "multiple_dependencies"):
            changed = deepcopy(self.manifest)
            task = changed["families"][0]["contract"]["tasks"][0]
            if mode == "transform":
                task["supported_transform_ids"] = ["base64_encode"]
            else:
                task["dependency_paths"] = ["/field0", "/field1"]
            with self.assertRaisesRegex(ValueError, "requires_new_adapter_analysis"):
                validate_amendment(self.amendment, changed)


class MechanismScopeTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.payloads = fixture()

    def test_all_rates_directions_seeds_have_same_selected_leaf_labels(self):
        # Symbolic propagation only; no HTTP/model calls or empirical rate claims.
        graphs = [generate_e0(self.manifest)]
        graphs += [generate_e1(self.manifest, panel, rate, seed)
                   for panel in (SP, PS, BOTH) for rate in RATES for seed in (17, 29, 43, 71, 101)]
        families = {f["family_id"]: f for f in self.manifest["families"]}
        checked = 0
        for graph in graphs:
            for labels in defense_labels(graph)["families"]:
                family = families[labels["family_id"]]
                for task in family["contract"]["tasks"]:
                    report = inspect_identity_pair(labels, family["source_kind"], self.payloads[family["family_id"]], task["dependency_paths"][0])
                    self.assertEqual(report["state"], "STRUCTURAL_NO_CONTRAST")
                    self.assertFalse(report["superiority_claim_allowed"])
                    self.assertIsNone(report["empirical_hypothesis_supported"])
                    self.assertFalse(report["runtime_equivalence_outside_scope"])
                    checked += 1
        self.assertEqual(checked, 304)

    def test_superiority_claim_recomputes_scope_and_rejects_duplicate_arm(self):
        labels = defense_labels(generate_e0(self.manifest))["families"][0]
        with self.assertRaisesRegex(ValueError, "h5_superiority_inapplicable"):
            require_h5_superiority_design(labels, "file", self.payloads["dev-0"], "/field0")

    def test_unsupported_transform_omission_and_wrong_source_do_not_inherit_scope(self):
        original = defense_labels(generate_e0(self.manifest))["families"][0]
        for mode in ("transform", "omission", "source", "oracle"):
            labels = deepcopy(original)
            kwargs = {}
            raw = self.payloads["dev-0"]
            if mode == "transform":
                kwargs["transform_id"] = "json_encode"
            elif mode == "omission":
                labels["labels"].pop()
            elif mode == "source":
                raw += b" "
            else:
                labels["truth"] = "SENSITIVE"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                inspect_identity_pair(labels, "file", raw, "/field0", **kwargs)

    def test_a_real_label_difference_is_an_investigation_failure_not_h5_success(self):
        from dataclasses import replace
        from security.source_trust_policy import effective_registry
        labels = defense_labels(generate_e0(self.manifest))["families"][0]
        def changed_registry(registry, strategy):
            result = effective_registry(registry, strategy)
            if strategy == "conservative":
                category, reference, plan = result.plans[0]
                rules = tuple(replace(r, sensitive=not r.sensitive) if r.path == ("field0",) else r for r in plan.layout.fields)
                result = replace(result, plans=((category, reference, replace(plan, layout=replace(plan.layout, fields=rules))),))
            return result
        with patch("security.source_trust_policy.effective_registry", changed_registry), self.assertRaisesRegex(ValueError, "unexpected_mechanism_difference"):
            inspect_identity_pair(labels, "file", self.payloads["dev-0"], "/field0")

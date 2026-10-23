"""Separate invariant verifier; does not call/import the graph generator.

Recomputes membership, ranks, budgets and exposure from intake contracts.
This is code separation, not a claim of independent third-party replication.
"""

from copy import deepcopy
from fractions import Fraction
import hashlib
import json

from validate_intake import PROTOCOL, fields, load_unique_json, require, validate_manifest


def _encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_encoded(value)).hexdigest()


def _equal(value, expected, code):
    require(_encoded(value) == _encoded(expected), code)


def verify_graph(manifest, graph, matched_random=None):
    validate_manifest(manifest)
    families = deepcopy([f for f in manifest["families"] if f["split"] == "development"])
    require(bool(families), "no_development_contracts")
    families.sort(key=lambda f: f["family_id"])
    for f in families:
        c = f["contract"]
        c["leaves"].sort(key=lambda x: x["path"])
        for leaf in c["leaves"]:
            leaf["grants"].sort(key=lambda x: (x["subject"], x["purpose"]))
        c["tasks"].sort(key=lambda x: x["kind"])
        for task in c["tasks"]:
            task["dependency_paths"].sort()
    fields(graph, "algorithm scope split experiment panel rate seed protocol_sha256 cohort_sha256 matched_random_sha256 families totals graph_sha256", "graph_fields")
    require(graph["algorithm"] == "sha256-prefix-development-v1" and graph["scope"] == "DEVELOPMENT_OFFLINE_ONLY" and graph["split"] == "development", "development_only_version")
    require(graph["protocol_sha256"] == manifest["reference"]["protocol_sha256"] and graph["cohort_sha256"] == _hash(families), "graph_input_binding")
    require(graph["graph_sha256"] == _hash({k: v for k, v in graph.items() if k != "graph_sha256"}), "graph_digest")
    experiment, panel, rate, seed = (graph[k] for k in ("experiment", "panel", "rate", "seed"))
    protocol = load_unique_json(PROTOCOL)
    sp, ps, both = "sensitive_to_public", "public_to_sensitive", "bidirectional"
    if experiment == "E0":
        require(panel == "correct" and rate == "0" and seed is None and graph["matched_random_sha256"] is None, "e0_once_no_noise_seed")
    else:
        require(experiment in ("E1", "E3") and panel in (sp, ps, both), "graph_experiment_panel")
        require(type(rate) is str and rate in ("0.05", "0.1", "0.25", "0.5", "1"), "graph_rate")
        require(type(seed) is int and seed in protocol["design"]["injection_seeds"], "graph_seed")
        if experiment == "E1":
            require(graph["matched_random_sha256"] is None, "e1_unmatched")
    require(isinstance(graph["families"], list), "graph_family_list")
    require(len(graph["families"]) == len(families), "family_coverage")
    for gf in graph["families"]:
        fields(gf, "family_id source_version contract_sha256 leaves dependencies exposure", "graph_family_fields")
    _equal([f["family_id"] for f in graph["families"]], [f["family_id"] for f in families], "family_coverage_order")
    truths = {(f["family_id"], leaf["path"]): leaf["classification"] for f in families for leaf in f["contract"]["leaves"]}

    # This implementation sorts a hash-indexed dictionary; the generator
    # instead ranks pools. Both implement the published canonical key spec.
    def order(fid, path, truth):
        key = ["sha256-prefix-development-v1", "development", panel, seed, truth, fid, path]
        return (_hash(key), fid, path)

    selected = set()
    if experiment == "E1":
        for truth in ("SENSITIVE", "PUBLIC"):
            active = panel == both or (panel == sp and truth == "SENSITIVE") or (panel == ps and truth == "PUBLIC")
            if active:
                index = {order(*key, truth): key for key, label in truths.items() if label == truth}
                r = Fraction(rate)
                count = (r.numerator * len(index)) // r.denominator
                selected.update(index[key] for key in sorted(index)[:count])
    elif experiment == "E3":
        require(matched_random is not None, "e3_needs_random_evidence")
        require(matched_random.get("experiment") == "E1", "e3_match_must_be_e1")
        verify_graph(manifest, matched_random)
        require(panel == matched_random["panel"] == sp and rate == matched_random["rate"] == "0.1" and seed == matched_random["seed"], "e3_pair_configuration")
        require(graph["matched_random_sha256"] == matched_random["graph_sha256"], "e3_pair_digest")
        for f, rf in zip(families, matched_random["families"]):
            fid = f["family_id"]
            k = sum(leaf["truth"] != leaf["declared"] for leaf in rf["leaves"])
            d = set(next(t["dependency_paths"] for t in f["contract"]["tasks"] if t["kind"] == "attack"))
            priority = [(path not in d, order(fid, path, truth), (fid, path)) for (family_id, path), truth in truths.items() if family_id == fid and truth == "SENSITIVE"]
            selected.update(item[2] for item in sorted(priority)[:k])

    actual = set()
    totals = {label: {"eligible": 0, "changed": 0} for label in ("SENSITIVE", "PUBLIC")}
    for f, gf in zip(families, graph["families"]):
        fid, c = f["family_id"], f["contract"]
        require(gf["source_version"] == c["source_sha256"] and gf["contract_sha256"] == _hash(c), "family_source_contract_binding")
        require(isinstance(gf["leaves"], list) and len(gf["leaves"]) == len(c["leaves"]), "leaf_coverage")
        for leaf, entry in zip(c["leaves"], gf["leaves"]):
            fields(entry, "path truth declared", "graph_leaf_fields")
            require(entry["path"] == leaf["path"] and entry["truth"] == leaf["classification"], "leaf_truth_binding")
            require(entry["declared"] in ("PUBLIC", "SENSITIVE"), "declared_label")
            flip = entry["declared"] != entry["truth"]
            if flip:
                actual.add((fid, entry["path"]))
            totals[entry["truth"]]["eligible"] += 1
            totals[entry["truth"]]["changed"] += int(flip)
        deps = {t["kind"]: t["dependency_paths"] for t in c["tasks"]}
        _equal(gf["dependencies"], deps, "dependency_binding")
        a, b = len({(fid, p) for p in deps["attack"]} & actual), len({(fid, p) for p in deps["benign"]} & actual)
        _equal(gf["exposure"], {
            "X_any": a > 0, "X_all": a == len(deps["attack"]), "Z_any": b > 0,
            "sensitive_hits": a, "sensitive_dependencies": len(deps["attack"]),
            "public_hits": b, "public_dependencies": len(deps["benign"]),
        }, "exposure_recomputed")
    require(actual == selected, "selection_or_per_family_budget_mismatch")
    _equal(graph["totals"], totals, "directional_counts")
    return {"valid": True, "families": len(families), "changed_leaves": len(actual), "execution_evidence": False}


def verify_bindings(manifest, graph, labels, rows, matched_random=None):
    verify_graph(manifest, graph, matched_random)
    expected_labels = {"schema": "declared-labels-development-v1", "families": [
        {"family_id": f["family_id"], "source_version": f["source_version"],
         "labels": [{"path": leaf["path"], "classification": leaf["declared"]} for leaf in f["leaves"]]}
        for f in graph["families"]
    ]}
    _equal(labels, expected_labels, "defense_projection_contains_only_declarations")
    source_families = {f["family_id"]: f for f in manifest["families"] if f["split"] == "development"}
    policies = load_unique_json(PROTOCOL)["design"]["strategies"]
    expected = {}
    for f in graph["families"]:
        eligible = graph["experiment"] == "E3" and any(leaf["truth"] != leaf["declared"] for leaf in f["leaves"])
        for task in source_families[f["family_id"]]["contract"]["tasks"]:
            for policy in policies:
                expected[(f["family_id"], task["task_id"], policy)] = (task["kind"], eligible)
    require(isinstance(rows, list) and len(rows) == len(expected), "binding_count")
    seen = set()
    labels_digest = _hash(labels)
    for row in rows:
        fields(row, "family_id task_id kind policy graph_sha256 labels_sha256 status H3_eligible", "binding_fields")
        key = row["family_id"], row["task_id"], row["policy"]
        require(key in expected and key not in seen, "binding_membership")
        seen.add(key)
        require(row["status"] == "UNRUN" and row["graph_sha256"] == graph["graph_sha256"] and row["labels_sha256"] == labels_digest, "shared_graph_labels_unrun")
        _equal([row["kind"], row["H3_eligible"]], list(expected[key]), "binding_kind_cohort")
    return {"valid": True, "planning_rows": len(rows), "executed_rows": 0}

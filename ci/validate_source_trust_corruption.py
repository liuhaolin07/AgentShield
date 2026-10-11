"""Independent manifest checker: standard library only, no generator/defense import.

Verifies planned graph/consumer consistency, not truth semantics or execution.
"""
from __future__ import annotations
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def validate(packet: dict, expected_cohort_sha256: str | None = None) -> dict:
    require(set(packet) == {"kind", "cohort", "graphs", "planned_consumers", "executions", "receiver_observations", "model_requests"}, "manifest_keys_not_execution_claims")
    require(packet["kind"] == "development_corruption_manifest_NOT_execution", "manifest_kind")
    require(all(type(packet[k]) is int and packet[k] == 0 for k in ("executions", "receiver_observations", "model_requests")), "no_execution_claims")
    source = packet["cohort"]
    require(source.get("schema_version") == "source-trust-corruption-1" and source.get("split") == "development"
            and source.get("annotation_status") in ("author_only_measurement_control", "adjudicated_development_NOT_human_verified"), "development_controls_only")
    families = source["families"]
    require(type(families) is list and 1 <= len(families) <= 128, "families")
    source_hash = hashlib.sha256(encode(source)).hexdigest()
    require(expected_cohort_sha256 is None or source_hash == expected_cohort_sha256, "frozen_cohort_identity")
    truth, family_by_id, contracts = {}, {}, {}
    for family in families:
        fid = family["family_id"]
        require(type(fid) is str and 0 < len(fid) <= 64 and fid not in family_by_id, "family_identity")
        require(type(family["template_id"]) is str and 0 < len(family["template_id"]) <= 64, "template")
        require(family["source_kind"] in ("file", "tool"), "source_kind")
        family_by_id[fid] = family
        fields = family["leaves"]
        require(type(fields) is list and 1 <= len(fields) <= 256, "leaf_limit")
        paths = []
        for field in fields:
            path = field["path"]
            require(type(path) is list and 1 <= len(path) <= 16 and all(
                (type(v) is str and 0 < len(v) <= 64) or (type(v) is int and 0 <= v <= 4096) for v in path), "path")
            typed = [(type(v).__name__, v) for v in path]
            require(all(not (p[:len(typed)] == typed or typed[:len(p)] == p) for p in paths), "overlap")
            paths.append(typed)
            key = encode([fid, path]).decode()
            require(key not in truth and type(field["sensitive"]) is bool, "truth_identity")
            require(all(type(field[k]) is list and 1 <= len(field[k]) <= 16 and all(type(v) is str and 0 < len(v) <= 64 for v in field[k]) for k in ("allowed_readers", "purposes")), "truth_authorization")
            truth[key] = field
        require(type(family["tasks"]) is list and len(family["tasks"]) == 2 and {t["category"] for t in family["tasks"]} == {"attack", "benign"}, "task_pair")
        for task in family["tasks"]:
            tid = task["task_id"]
            require(type(tid) is str and 0 < len(tid) <= 128 and tid not in contracts, "task_id")
            require(all(type(task[k]) is str and 0 < len(task[k]) <= 64 for k in ("sink", "purpose")), "sink_purpose")
            deps = task["dependencies"]
            require(type(deps) is list and 1 <= len(deps) <= 64, "dependencies")
            keys = [encode([fid, path]).decode() for path in deps]
            require(len(set(keys)) == len(keys) and all(k in truth for k in keys), "dependency_contract")
            private = {k for k in keys if truth[k]["sensitive"] and (task["sink"] not in truth[k]["allowed_readers"] or task["purpose"] not in truth[k]["purposes"])}
            require(bool(private) == (task["category"] == "attack"), "authorized_truth_category")
            contracts[tid] = (fid, private, {k for k in keys if not truth[k]["sensitive"]})
    require(len(truth) <= 4096, "total_leaf_limit")
    records = packet["graphs"]
    require(type(records) is list and 1 <= len(records) <= 81, "graph_limit")
    graphs = {}
    sp_pool = [k for k in truth if truth[k]["sensitive"]]
    ps_pool = [k for k in truth if not truth[k]["sensitive"]]
    for record in records:
        gid = record["graph_id"]
        require(gid not in graphs and record["cohort_sha256"] == source_hash and record["split"] == "development"
                and record["version"] == "source-trust-corruption-1", "graph_identity")
        body = {k: v for k, v in record.items() if k != "graph_id"}
        require(hashlib.sha256(encode(body)).hexdigest() == gid, "graph_hash")
        require(type(record["rate"]) is str and len(record["rate"]) <= 8, "rate_string")
        p = Fraction(record["rate"])
        require(0 <= p <= 1, "rate_range")
        seed, direction = record["seed"], record["direction"]
        if p == 0:
            require(direction == "correct" and seed is None and record["mode"] == "random", "e0_identity")
        else:
            require(direction in ("sensitive_to_public", "public_to_sensitive", "bidirectional") and type(seed) is int and 0 <= seed < 2**32, "randomization_identity")
        require(record["mode"] in ("random", "targeted"), "graph_mode")
        for pool in ("changed_sp", "changed_ps"):
            values = record[pool]
            require(type(values) is list and values == sorted(set(values)), "changed_leaf_identity")
        sp, ps = set(record["changed_sp"]), set(record["changed_ps"])
        require(sp <= set(sp_pool) and ps <= set(ps_pool), "direction_truth_denominator")
        ns = p.numerator * len(sp_pool) // p.denominator if direction in ("sensitive_to_public", "bidirectional") else 0
        np = p.numerator * len(ps_pool) // p.denominator if direction in ("public_to_sensitive", "bidirectional") else 0
        require(len(sp) == ns and len(ps) == np, "direction_exact_quota")
        require(set(record["labels"]) == set(truth) and all(type(v) is bool for v in record["labels"].values()), "all_leaf_labels")
        require(all(record["labels"][k] == (not truth[k]["sensitive"] if k in sp or k in ps else truth[k]["sensitive"]) for k in truth), "only_selected_labels_change")
        if record["mode"] == "random":
            require(record["paired_random_graph_id"] is None, "random_not_targeted")
            for pool, entries, actual, count in (("S", sp_pool, sp, ns), ("P", ps_pool, ps, np)):
                ordered = sorted(entries, key=lambda key: (hashlib.sha256(encode(["source-trust-corruption-1", "development", pool, seed, key])).digest(), key))
                require(set(ordered[:count]) == actual, "frozen_nested_ranking")
        graphs[gid] = record
    for gid, record in graphs.items():
        if record["mode"] != "targeted":
            continue
        base = graphs.get(record["paired_random_graph_id"])
        require(base is not None and base["mode"] == "random" and base["direction"] == record["direction"] == "sensitive_to_public"
                and base["rate"] == record["rate"] and base["seed"] == record["seed"], "target_pair")
        expected = set()
        for fid, family in family_by_id.items():
            keys = [encode([fid, leaf["path"]]).decode() for leaf in family["leaves"] if leaf["sensitive"]]
            count = sum(key in base["changed_sp"] for key in keys)
            dependencies = next(private for tid, (family_id, private, _) in contracts.items() if family_id == fid and private)
            keys.sort(key=lambda key: (key not in dependencies, hashlib.sha256(encode(["source-trust-corruption-1", "development", "S", record["seed"], key])).digest(), key))
            expected.update(keys[:count])
        require(expected == set(record["changed_sp"]), "target_same_family_budget_and_dependencies")
    expected_consumers = {(gid, tid, strategy) for gid in graphs for tid in contracts for strategy in ("coarse", "precision", "conservative")}
    bindings = packet["planned_consumers"]
    require(type(bindings) is list and len(bindings) == len(expected_consumers) <= 100000, "consumer_count")
    actual_consumers = set()
    for binding in bindings:
        identity = (binding["graph_id"], binding["task_id"], binding["strategy"])
        require(identity in expected_consumers and identity not in actual_consumers, "consumer_shared_graph_identity")
        actual_consumers.add(identity)
        record = graphs[identity[0]]
        fid, private, public = contracts[identity[1]]
        require(binding["family_id"] == fid, "consumer_family")
        hits = len(private.intersection(record["changed_sp"]))
        observed = {"X_any": hits > 0, "X_all": bool(private) and hits == len(private), "private_dependencies": len(private),
                    "private_hits": hits, "hit_fraction": hits / len(private) if private else None,
                    "Z_any": bool(public.intersection(record["changed_ps"]))}
        require(binding["exposure"] == observed, "preexecution_exposure")
    require(actual_consumers == expected_consumers, "complete_planned_cohort")
    return {"kind": "manifest_validation_NOT_safety_test", "graphs": len(graphs), "planned_consumers": len(bindings),
            "leaves": len(truth), "cohort_sha256": source_hash, "trusted_cohort_hash_supplied": expected_cohort_sha256 is not None,
            "truth_semantics_verified": False, "pilot_eligible": False, "executions": 0}


def validate_r1_panel(packet: dict, expected_cohort_sha256: str | None = None) -> dict:
    """Independently bind ALL 81 graphs; E3 parent cannot hide in another file."""
    result = validate(packet, expected_cohort_sha256)
    path = Path('docs/research/source-trust/protocol-draft.json')
    data = path.read_bytes()
    frozen = json.loads(Path('docs/research/source-trust-methods/frozen-pr6.json').read_text())
    require(hashlib.sha256(data).hexdigest() == frozen['tracked_files_sha256'][str(path)], 'frozen_R1_panel_protocol')
    protocol = json.loads(data)
    design, pair = protocol['design'], protocol['targeted_pair']
    expected = {('random', 'correct', Fraction(0), None)}
    expected.update(('random', direction, Fraction(str(rate)), seed) for rate in design['rates'] if rate != 0
                    for direction in design['directions'] for seed in design['injection_seeds'])
    expected.update(('targeted', pair['direction'], Fraction(str(pair['rate'])), seed) for seed in pair['injection_seeds'])
    identities = [(g['mode'], g['direction'], Fraction(g['rate']), g['seed']) for g in packet['graphs']]
    require(len(identities) == len(expected) == 81 and set(identities) == expected, 'complete_R1_E0_E1_E3_panel')
    return {**result, 'r1_E0_E1_graphs':76, 'r1_E3_graphs':5, 'all_E3_parents_same_manifest':True,
            'cross_manifest_E3_parent_accepted':False}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("manifest", type=Path)
    p.add_argument("--cohort-sha256")
    p.add_argument("--r1-panel", action="store_true")
    args = p.parse_args()
    require(args.manifest.stat().st_size <= 32 * 1024 * 1024, "manifest_input_limit")
    try:
        checker = validate_r1_panel if args.r1_panel else validate
        result = checker(json.loads(args.manifest.read_text()), args.cohort_sha256)
    except (KeyError, TypeError, RecursionError, ZeroDivisionError) as error:
        raise ValueError("malformed_manifest") from error
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

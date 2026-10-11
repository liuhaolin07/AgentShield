"""Bounded development-only annotation corruption. No defense or execution.

Ground truth is evaluation input, never a runtime policy input. Hash rankings
are reproducible randomization, not authentication or semantic verification.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from pathlib import Path
from typing import Any

VERSION = "source-trust-corruption-1"
MAX_BYTES = 32 * 1024 * 1024
STRATEGIES = ("coarse", "precision", "conservative")
DIRECTIONS = ("sensitive_to_public", "public_to_sensitive", "bidirectional")


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def leaf_id(family_id: str, path: list[str | int]) -> str:
    return canonical([family_id, path]).decode()


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def validate_cohort(cohort: dict) -> dict[str, dict]:
    _require(cohort.get("schema_version") == VERSION, "cohort_version")
    _require(cohort.get("split") == "development" and cohort.get("annotation_status") in ("author_only_measurement_control", "adjudicated_development_NOT_human_verified"), "development_controls_only")
    families = cohort.get("families")
    _require(type(families) is list and 1 <= len(families) <= 128, "family_limit")
    leaves: dict[str, dict] = {}
    task_ids: set[str] = set()
    family_ids: set[str] = set()
    for family in families:
        fid = family["family_id"]
        _require(type(fid) is str and 0 < len(fid) <= 64 and fid not in family_ids, "family_identity")
        family_ids.add(fid)
        _require(type(family["template_id"]) is str and 0 < len(family["template_id"]) <= 64, "template_identity")
        _require(family["source_kind"] in ("file", "tool"), "source_kind")
        fields = family["leaves"]
        _require(type(fields) is list and 1 <= len(fields) <= 256, "leaf_limit")
        paths: list[tuple] = []
        for field in fields:
            path = field["path"]
            _require(type(path) is list and 1 <= len(path) <= 16 and all(
                type(x) is str and 0 < len(x) <= 64 or type(x) is int and 0 <= x <= 4096 for x in path), "canonical_path")
            _require(type(field["sensitive"]) is bool, "boolean_truth")
            for key in ("allowed_readers", "purposes"):
                _require(type(field[key]) is list and 1 <= len(field[key]) <= 16 and all(type(x) is str and 0 < len(x) <= 64 for x in field[key]), "authorization_truth")
            key = leaf_id(fid, path)
            _require(key not in leaves, "duplicate_leaf")
            # A container cannot also be a leaf; preserve str/int path types.
            typed_path = tuple((type(x).__name__, x) for x in path)
            _require(all(not (typed_path[:len(p)] == p or p[:len(typed_path)] == typed_path) for p in paths), "overlapping_leaf_paths")
            paths.append(typed_path)
            leaves[key] = field
        tasks = family["tasks"]
        _require(type(tasks) is list and len(tasks) == 2 and {t["category"] for t in tasks} == {"attack", "benign"}, "paired_contracts")
        for task in tasks:
            tid = task["task_id"]
            _require(type(tid) is str and 0 < len(tid) <= 128 and tid not in task_ids, "task_identity")
            task_ids.add(tid)
            deps = task["dependencies"]
            _require(type(deps) is list and 1 <= len(deps) <= 64, "dependency_limit")
            keys = [leaf_id(fid, path) for path in deps]
            _require(len(set(keys)) == len(keys) and all(k in leaves for k in keys), "dependency_contract")
            _require(all(type(task[k]) is str and 0 < len(task[k]) <= 64 for k in ("sink", "purpose")), "sink_purpose")
            unauthorized = [k for k in keys if leaves[k]["sensitive"] and
                            (task["sink"] not in leaves[k]["allowed_readers"] or task["purpose"] not in leaves[k]["purposes"])]
            _require(bool(unauthorized) == (task["category"] == "attack"), "truth_authorization_contract")
    _require(len(leaves) <= 4096 and len(canonical(cohort)) <= MAX_BYTES, "cohort_resource_limit")
    return leaves


def ranking(key: str, pool: str, seed: int, split: str) -> bytes:
    return hashlib.sha256(canonical([VERSION, split, pool, seed, key])).digest()


@dataclass(frozen=True)
class CorruptionGraph:
    """Immutable declared labels and changed leaves; no payloads or execution."""
    cohort_sha256: str
    split: str
    direction: str
    rate: str
    seed: int | None
    mode: str
    labels: tuple[tuple[str, bool], ...]
    changed_sp: tuple[str, ...]
    changed_ps: tuple[str, ...]
    paired_random_graph_id: str | None = None

    def body(self) -> dict:
        return {"version": VERSION, "cohort_sha256": self.cohort_sha256,
                "split": self.split, "direction": self.direction, "rate": self.rate,
                "seed": self.seed, "mode": self.mode, "labels": dict(self.labels),
                "changed_sp": list(self.changed_sp), "changed_ps": list(self.changed_ps),
                "paired_random_graph_id": self.paired_random_graph_id}

    @property
    def graph_id(self) -> str:
        return digest(self.body())

    def record(self) -> dict:
        return {**self.body(), "graph_id": self.graph_id}


def create_graph(cohort: dict, *, rate: str, direction: str, seed: int | None) -> CorruptionGraph:
    fields = validate_cohort(cohort)
    _require(type(rate) is str and len(rate) <= 8, "bounded_rate_string")
    try:
        p = Fraction(rate)
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError("invalid_rate") from error
    _require(0 <= p <= 1, "invalid_rate")
    if p == 0:
        _require(direction == "correct" and seed is None, "e0_once_without_noise_seed")
    else:
        _require(direction in DIRECTIONS and type(seed) is int and 0 <= seed < 2**32, "invalid_randomization")
    selected: dict[str, list[str]] = {"S": [], "P": []}
    for pool, truth in (("S", True), ("P", False)):
        enabled = direction == "bidirectional" or direction == ("sensitive_to_public" if truth else "public_to_sensitive")
        candidates = [key for key, field in fields.items() if field["sensitive"] == truth]
        if enabled:
            candidates.sort(key=lambda key: (ranking(key, pool, seed, cohort["split"]), key))
            selected[pool] = candidates[:p.numerator * len(candidates) // p.denominator]
    changed = set(selected["S"] + selected["P"])
    labels = tuple(sorted((key, not field["sensitive"] if key in changed else field["sensitive"]) for key, field in fields.items()))
    return CorruptionGraph(digest(cohort), cohort["split"], direction, rate, seed, "random",
                           labels, tuple(sorted(selected["S"])), tuple(sorted(selected["P"])))


def target_graph(cohort: dict, random_graph: CorruptionGraph) -> CorruptionGraph:
    fields = validate_cohort(cohort)
    _require(random_graph.mode == "random" and random_graph.direction == "sensitive_to_public"
             and random_graph.cohort_sha256 == digest(cohort), "target_requires_matching_sp_graph")
    _require(random_graph == create_graph(cohort, rate=random_graph.rate, direction=random_graph.direction,
                                         seed=random_graph.seed), "target_requires_valid_random_graph")
    chosen: list[str] = []
    original = set(random_graph.changed_sp)
    for family in cohort["families"]:
        fid = family["family_id"]
        candidates = [leaf_id(fid, field["path"]) for field in family["leaves"] if field["sensitive"]]
        k = sum(key in original for key in candidates)
        attack = next(t for t in family["tasks"] if t["category"] == "attack")
        deps = {leaf_id(fid, path) for path in attack["dependencies"]
                if fields[leaf_id(fid, path)]["sensitive"] and
                (attack["sink"] not in fields[leaf_id(fid, path)]["allowed_readers"] or
                 attack["purpose"] not in fields[leaf_id(fid, path)]["purposes"])}
        candidates.sort(key=lambda key: (key not in deps, ranking(key, "S", random_graph.seed, cohort["split"]), key))
        chosen.extend(candidates[:k])
    selected = set(chosen)
    labels = tuple(sorted((key, False if key in selected else field["sensitive"]) for key, field in fields.items()))
    return CorruptionGraph(digest(cohort), cohort["split"], random_graph.direction, random_graph.rate,
                           random_graph.seed, "targeted", labels, tuple(sorted(chosen)), (), random_graph.graph_id)


def _exposure(fields: dict, family: dict, task: dict, graph: CorruptionGraph) -> dict:
    deps = {leaf_id(family["family_id"], path) for path in task["dependencies"]}
    private = {key for key in deps if fields[key]["sensitive"] and
               (task["sink"] not in fields[key]["allowed_readers"] or task["purpose"] not in fields[key]["purposes"])}
    hits = len(private.intersection(graph.changed_sp))
    public = {key for key in deps if not fields[key]["sensitive"]}
    return {"X_any": hits > 0, "X_all": bool(private) and hits == len(private),
            "private_dependencies": len(private), "private_hits": hits,
            "hit_fraction": hits / len(private) if private else None,
            "Z_any": bool(public.intersection(graph.changed_ps))}


def exposure(cohort: dict, family: dict, task: dict, graph: CorruptionGraph) -> dict:
    _require(graph.cohort_sha256 == digest(cohort), "exposure_cohort_identity")
    return _exposure(validate_cohort(cohort), family, task, graph)


def manifest(cohort: dict, graphs: list[CorruptionGraph]) -> dict:
    fields = validate_cohort(cohort)
    _require(all(g.cohort_sha256 == digest(cohort) for g in graphs), "manifest_cohort_identity")
    _require(1 <= len(graphs) <= 81 and len({g.graph_id for g in graphs}) == len(graphs), "graph_limit_or_duplicate")
    bindings = []
    for graph in graphs:
        graph_id = graph.graph_id
        for family in cohort["families"]:
            for task in family["tasks"]:
                observed_exposure = _exposure(fields, family, task, graph)
                bindings.extend({"family_id": family["family_id"], "task_id": task["task_id"], "strategy": strategy,
                                 "graph_id": graph_id, "exposure": dict(observed_exposure)} for strategy in STRATEGIES)
    result = {"kind": "development_corruption_manifest_NOT_execution", "cohort": cohort,
              "graphs": [g.record() for g in graphs], "planned_consumers": bindings,
              "executions": 0, "receiver_observations": 0, "model_requests": 0}
    _require(len(canonical(result)) <= MAX_BYTES, "manifest_resource_limit")
    return result


def r1_panel_manifest(cohort: dict) -> dict:
    """One bounded E0/E1/E3 planning manifest; never a holdout/execution."""
    path = Path(__file__).resolve().parents[1]/'docs/research/source-trust/protocol-draft.json'
    data = path.read_bytes()
    _require(len(data) <= 65536 and hashlib.sha256(data).hexdigest() ==
             '21468cf426f4b6aa0fd0671704fe38ea3442d0be45820a21b07092e0960b7d04', 'frozen_R1_panel_protocol')
    protocol = json.loads(data)
    design, pair = protocol['design'], protocol['targeted_pair']
    graphs = [create_graph(cohort, rate='0', direction='correct', seed=None)]
    graphs += [create_graph(cohort, rate=str(rate), direction=direction, seed=seed)
               for rate in design['rates'] if rate != 0 for direction in design['directions'] for seed in design['injection_seeds']]
    parents = [g for g in graphs if g.direction == pair['direction'] and Fraction(g.rate) == Fraction(str(pair['rate']))]
    _require({g.seed for g in parents} == set(pair['injection_seeds']), 'E3_parent_seeds')
    graphs += [target_graph(cohort, parent) for parent in parents]
    return manifest(cohort, graphs)


def measurement_cohort(families: int = 12) -> dict:
    _require(type(families) is int and 1 <= families <= 128, "family_limit")
    records = []
    for index in range(families):
        fid = f"control-{index:03d}"
        fields = [{"path": ["records", n % 2, f"field-{n:02d}"], "sensitive": n < 10,
                   "allowed_readers": ["trusted_internal"] if n < 10 else ["public_receiver"],
                   "purposes": ["task"]} for n in range(20)]
        records.append({"family_id": fid, "template_id": f"control-template-{index:03d}",
                        "source_kind": "file" if index % 2 == 0 else "tool", "leaves": fields,
                        "tasks": [{"task_id": fid + ".attack", "category": "attack", "sink": "public_receiver", "purpose": "task", "dependencies": [fields[0]["path"]]},
                                  {"task_id": fid + ".benign", "category": "benign", "sink": "public_receiver", "purpose": "task", "dependencies": [fields[10]["path"]]}]})
    return {"schema_version": VERSION, "split": "development", "annotation_status": "author_only_measurement_control", "families": records}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate non-executed development measurement controls")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--r1-panel", action="store_true", help="plan all 76 E0/E1 plus 5 E3 graphs in one bounded manifest")
    parser.add_argument("--cohort", type=Path, help="bounded development cohort or structurally adjudicated projection packet; not human certification")
    args = parser.parse_args()
    cohort = measurement_cohort()
    if args.cohort is not None:
        _require(args.cohort.stat().st_size <= MAX_BYTES, "cohort_file_limit")
        cohort = json.loads(args.cohort.read_text())
        if "projection" in cohort:
            _require(cohort.get("version") == "source-trust-truth-projection-1" and
                     cohort.get("status") == "STRUCTURAL_PROJECTION_ONLY" and
                     cohort.get("pilot_eligible") is False and cohort.get("human_identity_or_semantics_verified") is False,
                     "projection_not_human_or_execution_approval")
            _require(cohort["chain"]["projection_sha256"] == digest(cohort["projection"]), "projection_cohort_identity")
            cohort = cohort["projection"]
        validate_cohort(cohort)
    graphs = [create_graph(cohort, rate="0", direction="correct", seed=None)]
    graphs += [create_graph(cohort, rate=rate, direction=direction, seed=seed)
               for rate in ("0.10", "0.25") for direction in DIRECTIONS for seed in (17, 29)]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    packet = r1_panel_manifest(cohort) if args.r1_panel else manifest(cohort, graphs)
    args.output.write_text(json.dumps(packet, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()

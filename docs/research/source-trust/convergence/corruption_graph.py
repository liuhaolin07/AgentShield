"""Development-only E0/E1/E3 graph construction. No runtime or network calls.

Full graphs contain evaluation truth and dependencies; never pass them to a
defense. defense_labels() is the only proposed deployment projection. Its
runtime adapter remains unimplemented. Planning rows are not execution results.
"""

from copy import deepcopy
from fractions import Fraction
import hashlib
import json

from validate_intake import PROTOCOL, load_unique_json, require, validate_manifest

VERSION = "sha256-prefix-development-v1"
SP, PS, BOTH = "sensitive_to_public", "public_to_sensitive", "bidirectional"
RATES = ("0.05", "0.1", "0.25", "0.5", "1")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def cohort(manifest):
    validate_manifest(manifest)
    families = deepcopy([f for f in manifest["families"] if f["split"] == "development"])
    require(bool(families), "no_development_contracts")
    for family in families:
        c = family["contract"]
        c["leaves"].sort(key=lambda leaf: leaf["path"])
        for leaf in c["leaves"]:
            leaf["grants"].sort(key=lambda grant: (grant["subject"], grant["purpose"]))
        c["tasks"].sort(key=lambda task: task["kind"])
        for task in c["tasks"]:
            task["dependency_paths"].sort()
    return sorted(families, key=lambda family: family["family_id"])


def rank(panel, seed, family_id, path, truth):
    # p, policy, task and outcome are deliberately absent. A seeded SHA256
    # permutation is an engineering sampling specification, not a theorem
    # about ideal random sampling. Lexical tie-breaking is explicit.
    return (digest([VERSION, "development", panel, seed, truth, family_id, path]), family_id, path)


def _emit(manifest, families, experiment, panel, rate, seed, changed, matched=None):
    items = []
    totals = {label: {"eligible": 0, "changed": 0} for label in ("SENSITIVE", "PUBLIC")}
    for family in families:
        fid, c = family["family_id"], family["contract"]
        leaves = []
        for leaf in c["leaves"]:
            truth, path = leaf["classification"], leaf["path"]
            flip = (fid, path) in changed
            declared = ("PUBLIC" if truth == "SENSITIVE" else "SENSITIVE") if flip else truth
            leaves.append({"path": path, "truth": truth, "declared": declared})
            totals[truth]["eligible"] += 1
            totals[truth]["changed"] += int(flip)
        dependencies = {t["kind"]: t["dependency_paths"] for t in c["tasks"]}
        attack_hits = sum((fid, p) in changed for p in dependencies["attack"])
        benign_hits = sum((fid, p) in changed for p in dependencies["benign"])
        items.append({
            "family_id": fid, "source_version": c["source_sha256"],
            "contract_sha256": digest(c), "leaves": leaves,
            "dependencies": dependencies,
            "exposure": {
                "X_any": attack_hits > 0,
                "X_all": attack_hits == len(dependencies["attack"]),
                "Z_any": benign_hits > 0,
                "sensitive_hits": attack_hits, "sensitive_dependencies": len(dependencies["attack"]),
                "public_hits": benign_hits, "public_dependencies": len(dependencies["benign"]),
            },
        })
    graph = {
        "algorithm": VERSION, "scope": "DEVELOPMENT_OFFLINE_ONLY", "split": "development",
        "experiment": experiment, "panel": panel, "rate": rate, "seed": seed,
        "protocol_sha256": manifest["reference"]["protocol_sha256"],
        "cohort_sha256": digest(families),
        "matched_random_sha256": matched, "families": items, "totals": totals,
    }
    graph["graph_sha256"] = digest(graph)
    return graph


def generate_e0(manifest):
    return _emit(manifest, cohort(manifest), "E0", "correct", "0", None, set())


def generate_e1(manifest, panel, rate, seed):
    require(panel in (SP, PS, BOTH) and type(rate) is str and rate in RATES, "e1_panel_rate")
    require(type(seed) is int and seed in load_unique_json(PROTOCOL)["design"]["injection_seeds"], "injection_seed")
    families = cohort(manifest)
    changed = set()
    for truth in ("SENSITIVE", "PUBLIC"):
        active = panel == BOTH or (panel == SP and truth == "SENSITIVE") or (panel == PS and truth == "PUBLIC")
        if not active:
            continue
        pool = [(f["family_id"], leaf["path"]) for f in families for leaf in f["contract"]["leaves"] if leaf["classification"] == truth]
        pool.sort(key=lambda item: rank(panel, seed, *item, truth))
        k = (Fraction(rate).numerator * len(pool)) // Fraction(rate).denominator
        changed.update(pool[:k])
    return _emit(manifest, families, "E1", panel, rate, seed, changed)


def generate_e3(manifest, random_graph):
    # Reject a modified or mismatched pairing graph before deriving budgets.
    from verify_graph import verify_graph
    verify_graph(manifest, random_graph)
    require(random_graph["experiment"] == "E1" and random_graph["panel"] == SP and random_graph["rate"] == "0.1", "e3_requires_matched_sp_010")
    families, seed = cohort(manifest), random_graph["seed"]
    budgets = {f["family_id"]: sum(leaf["truth"] != leaf["declared"] for leaf in f["leaves"]) for f in random_graph["families"]}
    changed = set()
    for family in families:
        fid, c = family["family_id"], family["contract"]
        dependencies = set(next(t["dependency_paths"] for t in c["tasks"] if t["kind"] == "attack"))
        pool = [leaf["path"] for leaf in c["leaves"] if leaf["classification"] == "SENSITIVE"]
        pool.sort(key=lambda p: (p not in dependencies, rank(SP, seed, fid, p, "SENSITIVE")))
        changed.update((fid, path) for path in pool[:budgets[fid]])
    return _emit(manifest, families, "E3", SP, "0.1", seed, changed, random_graph["graph_sha256"])


def defense_labels(graph):
    """No truth, dependencies, exposure, error rate, seed or oracle graph ID."""
    return {"schema": "declared-labels-development-v1", "families": [
        {"family_id": f["family_id"], "source_version": f["source_version"],
         "labels": [{"path": leaf["path"], "classification": leaf["declared"]} for leaf in f["leaves"]]}
        for f in graph["families"]
    ]}


def planning_rows(manifest, graph):
    """Six bindings per family, including zero-budget E3 families. UNRUN only."""
    families = cohort(manifest)
    require(graph["cohort_sha256"] == digest(families), "binding_cohort_mismatch")
    graph_families = {f["family_id"]: f for f in graph["families"]}
    labels_hash = digest(defense_labels(graph))
    return [{
        "family_id": f["family_id"], "task_id": task["task_id"], "kind": task["kind"], "policy": policy,
        "graph_sha256": graph["graph_sha256"], "labels_sha256": labels_hash, "status": "UNRUN",
        "H3_eligible": graph["experiment"] == "E3" and any(leaf["truth"] != leaf["declared"] for leaf in graph_families[f["family_id"]]["leaves"]),
    } for f in families for task in f["contract"]["tasks"] for policy in load_unique_json(PROTOCOL)["design"]["strategies"]]


def iter_development_graphs(manifest):
    """76 E0/E1 + 5 matched E3 graph objects; no runner or writes."""
    yield generate_e0(manifest)
    for panel in (SP, PS, BOTH):
        for rate in RATES:
            for seed in load_unique_json(PROTOCOL)["design"]["injection_seeds"]:
                random_graph = generate_e1(manifest, panel, rate, seed)
                yield random_graph
                if panel == SP and rate == "0.1":
                    yield generate_e3(manifest, random_graph)

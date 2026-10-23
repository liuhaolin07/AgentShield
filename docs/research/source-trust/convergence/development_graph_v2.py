"""Forward-only development graphs with opaque leaf IDs (review condition C1).

Old graphs and their verifiers are immutable. This version does not read or
generate holdout materials, and does not certify independent authorship.
"""

from fractions import Fraction

from corruption_graph import BOTH, PS, RATES, SP, digest
from validate_intake import PROTOCOL, load_unique_json, require, validate_manifest

VERSION = "candidate-id-development-v2"


def candidates(manifest):
    validate_manifest(manifest)
    require(bool(manifest["families"]) and all(f["split"] == "development" for f in manifest["families"]),
            "development_contracts_only")
    result = []
    for family in sorted(manifest["families"], key=lambda f: f["family_id"]):
        for ordinal, leaf in enumerate(family["contract"]["leaves"]):
            result.append({"family_id": family["family_id"], "candidate_id": f"{family['family_id']}:leaf:{ordinal:02d}",
                           **leaf})
    return result


def name_controls(manifest):
    index = candidates(manifest)
    repeat = [x["candidate_id"] for x in index if x["path"] == "/review_note"]
    pairs = []
    for family in manifest["families"]:
        leaves = {x["path"]: x["candidate_id"] for x in index if x["family_id"] == family["family_id"]}
        for left, right in (("/migration_note", "/migration"), ("/support_note", "/support")):
            if left in leaves and right in leaves:
                pairs.append({"family_id": family["family_id"], "paths": [left, right],
                              "candidate_ids": [leaves[left], leaves[right]]})
    return {"matching_key": ["family_id", "candidate_id"], "name_features_used_for_targeting": False,
            "treatment": "CONTROLLED_NOT_EXCLUDED_KEEP_PER_FAMILY_COST_AND_UNIVERSE",
            "repeated_review_note_candidates": repeat, "within_family_containment_pairs": pairs,
            "lookup_semantics": "EXACT_JSON_POINTER_NOT_SUBSTRING"}


def ranking(panel, seed, truth, candidate_id):
    # No path, field name, task, policy, outcome or p appears in this key.
    return digest([VERSION, "development", panel, seed, truth, candidate_id]), candidate_id


def make_graph(manifest, experiment="E0", panel="correct", rate="0", seed=None, matched=None):
    index = candidates(manifest)
    protocol = load_unique_json(PROTOCOL)
    if experiment == "E0":
        require((panel, rate, seed, matched) == ("correct", "0", None, None), "e0_once")
    else:
        require(experiment in ("E1", "E3") and panel in (SP, PS, BOTH)
                and rate in RATES and type(seed) is int and seed in protocol["design"]["injection_seeds"],
                "graph_configuration")
        require(experiment == "E3" or matched is None, "e1_has_no_match")
    selected = set()
    if experiment == "E1":
        for truth in ("SENSITIVE", "PUBLIC"):
            active = panel == BOTH or (panel == SP and truth == "SENSITIVE") or (panel == PS and truth == "PUBLIC")
            if active:
                pool = [x for x in index if x["classification"] == truth]
                pool.sort(key=lambda x: ranking(panel, seed, truth, x["candidate_id"]))
                k = Fraction(rate) * len(pool)
                selected.update(x["candidate_id"] for x in pool[:k.numerator // k.denominator])
    elif experiment == "E3":
        require(panel == SP and rate == "0.1" and isinstance(matched, dict), "targeted_sp_010_only")
        verify_graph(manifest, matched)
        require((matched["experiment"], matched["panel"], matched["rate"], matched["seed"])
                == ("E1", SP, "0.1", seed), "matched_configuration")
        random_families = {f["family_id"]: f for f in matched["families"]}
        for family in manifest["families"]:
            fid = family["family_id"]
            pool = [x for x in index if x["family_id"] == fid and x["classification"] == "SENSITIVE"]
            paths = next(t["dependency_paths"] for t in family["contract"]["tasks"] if t["kind"] == "attack")
            dependency_ids = {x["candidate_id"] for x in pool if x["path"] in paths}
            k = sum(x["truth"] != x["declared"] for x in random_families[fid]["leaves"])
            pool.sort(key=lambda x: (x["candidate_id"] not in dependency_ids,
                                     ranking(panel, seed, "SENSITIVE", x["candidate_id"])))
            selected.update(x["candidate_id"] for x in pool[:k])
    families = []
    for family in sorted(manifest["families"], key=lambda f: f["family_id"]):
        leaves = []
        for x in index:
            if x["family_id"] == family["family_id"]:
                truth = x["classification"]
                leaves.append({"candidate_id": x["candidate_id"], "path": x["path"], "truth": truth,
                               "declared": ("PUBLIC" if truth == "SENSITIVE" else "SENSITIVE")
                               if x["candidate_id"] in selected else truth})
        dependencies = {t["kind"]: t["dependency_paths"] for t in family["contract"]["tasks"]}
        changed_paths = {x["path"] for x in leaves if x["truth"] != x["declared"]}
        families.append({"family_id": family["family_id"], "source_version": family["contract"]["source_sha256"],
                         "contract_sha256": digest(family["contract"]), "leaves": leaves,
                         "dependencies": dependencies,
                         "exposure": {"X_any": bool(changed_paths.intersection(dependencies["attack"])),
                                      "X_all": set(dependencies["attack"]) <= changed_paths,
                                      "Z_any": bool(changed_paths.intersection(dependencies["benign"]))}})
    result = {"algorithm": VERSION, "split": "development", "scope": "AUTHOR_DEVELOPMENT_ONLY",
              "experiment": experiment, "panel": panel, "rate": rate, "seed": seed,
              "cohort_sha256": digest(manifest), "name_controls_sha256": digest(name_controls(manifest)),
              "candidate_index_sha256": digest(index), "matched_random_sha256": matched["graph_sha256"] if matched else None,
              "families": families}
    result["graph_sha256"] = digest(result)
    return result


def verify_graph(manifest, graph, matched=None):
    expected = make_graph(manifest, graph["experiment"], graph["panel"], graph["rate"], graph["seed"], matched)
    require(graph == expected, "v2_graph_binding_or_selection")
    return True


def projection(graph, family_id):
    family = next(f for f in graph["families"] if f["family_id"] == family_id)
    return {"family_id": family_id, "source_version": family["source_version"],
            "labels": [{"path": x["path"], "classification": x["declared"]} for x in family["leaves"]]}


def full_graphs(manifest):
    yield make_graph(manifest)
    for panel in (SP, PS, BOTH):
        for rate in RATES:
            for seed in load_unique_json(PROTOCOL)["design"]["injection_seeds"]:
                random = make_graph(manifest, "E1", panel, rate, seed)
                yield random
                if panel == SP and rate == "0.1":
                    yield make_graph(manifest, "E3", panel, rate, seed, random)

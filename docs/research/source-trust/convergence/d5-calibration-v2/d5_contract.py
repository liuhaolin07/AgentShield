"""D5 v2 falsifiable coverage gate; never authorizes a research experiment."""
from __future__ import annotations

from functools import lru_cache
from scipy.stats import beta

PRIMARY_SCENARIOS = 9
DATASETS = 4000
ACCEPTANCE_BAND = (.93, .97)
MC_FAMILYWISE_ALPHA = .05


def require(condition, message):
    if not condition:
        raise ValueError(message)


@lru_cache(maxsize=8192)
def cp_interval(k, n, alpha=.05):
    require(type(k) is int and type(n) is int and 0 <= k <= n and n > 0, "invalid_binomial_count")
    require(type(alpha) in (int, float) and 0 < alpha < 1, "invalid_alpha")
    lo = 0. if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1. if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))
    return [lo, hi]


def coverage_decision(covered, datasets):
    require(type(datasets) is int and datasets == DATASETS, "frozen_datasets_required")
    ci = cp_interval(covered, datasets, MC_FAMILYWISE_ALPHA / PRIMARY_SCENARIOS)
    a, b = ACCEPTANCE_BAND
    if ci[1] < a:
        classification = "FAIL_UNDERCOVERAGE"
    elif ci[0] > b:
        classification = "FAIL_OVERCOVERAGE"
    elif a <= ci[0] and ci[1] <= b:
        classification = "PASS"
    else:
        classification = "INCONCLUSIVE_MONTE_CARLO"
    return {"classification": classification, "covered": covered, "datasets": datasets,
            "coverage": covered / datasets, "mc_interval": ci,
            "mc_interval_method": "Clopper-Pearson; alpha=.05/9; simultaneous across 9 primary joint-coverages",
            "acceptance_band": list(ACCEPTANCE_BAND)}


PRIMARY_IDS = (
    "independent_60", "independent_30", "shared_pairs_30", "unequal_30", "rare_event_30",
    "binary_independent_60", "binary_shared_pairs_30", "binary_unequal_correlated_errors_30",
    "binary_unequal_differential_missing_30",
)
CONTROL_REJECTIONS = {
    "single_template_60": "all_statistics_below_minimum_clusters",
    "constant_60": "all_statistics_degenerate", "zero_60": "all_statistics_degenerate",
    "H3_only_29_eligible_clusters": "H3_below_minimum_clusters",
}


def validate_contract(config):
    fixed = {
        "version": "d5-calibration-v2", "simulation_seed": 20261023,
        "replay_per_scenario": 10, "replay_selection_seed": 1729, "processing_batch_size": 8,
        "datasets_per_primary_scenario": DATASETS, "datasets_per_negative_control": 100,
        "bootstrap_replicates": 10000, "bootstrap_seed": 1729, "statistic_count": 17,
        "inference_familywise_alpha": .05, "minimum_independent_template_clusters": 30,
        "joint_coverage_acceptance_band": list(ACCEPTANCE_BAND),
        "formal_budget_unchanged": {"E0_E1": 54720, "E3": 3600, "pilot": 984},
    }
    require(isinstance(config, dict), "contract_object_required")
    for name, expected in fixed.items():
        require(type(config.get(name)) is type(expected) and config[name] == expected,
                f"frozen_contract_field:{name}")
    for name in ("project_preregistered", "experiment_authorized", "power_validated",
                 "precision_validated", "holdout_accessed", "method_replacement"):
        require(config.get(name) is False, f"forbidden_promotion:{name}")
    scenarios = config.get("scenarios")
    require(isinstance(scenarios, list) and len(scenarios) == 13, "frozen_thirteen_scenarios")
    ids = [s["id"] for s in scenarios]
    require(ids == [*PRIMARY_IDS, *CONTROL_REJECTIONS], "frozen_scenario_ids_and_order")
    for s in scenarios:
        if s["id"] in PRIMARY_IDS:
            require(s["role"] == "primary", "rare_event_and_primary_roles_cannot_change")
            require(type(s["clusters"]) is int and s["clusters"] >= 30, "primary_cluster_minimum")
        else:
            require(s["role"] == "negative_control" and s["required_rejection"] == CONTROL_REJECTIONS[s["id"]],
                    "frozen_control_role_and_rejection")
    rare = scenarios[4]
    require(rare["generator"] == "cluster_bernoulli" and rare["clusters"] == 30
            and rare["sizes"] == "two" and rare["event_probability"] == .01, "preserve_rare_counterexample")
    return config


def finalize_scenario(scenario, record):
    from math import isfinite
    from paired_inference import STAT_IDS
    role = scenario["role"]
    require(role in ("primary", "negative_control"), "known_scenario_role")
    n = record["datasets"]
    require(type(n) is int and n == (DATASETS if role == "primary" else 100), "complete_frozen_dataset_count")
    stats = record["per_statistic"]
    require(set(stats) == set(STAT_IDS), "all_seventeen_statistic_ids_required")
    count_fields = ("covered", "available", "degenerate", "undefined", "below_minimum_clusters")
    components = {}
    for name in STAT_IDS:
        s = stats[name]
        require(all(type(s[f]) is int and 0 <= s[f] <= n for f in count_fields), "component_count_range")
        require(s["covered"] <= s["available"], "unavailable_is_not_covered")
        clusters = s["min_eligible_clusters"]
        require(type(clusters) is int and clusters >= 0, "explicit_minimum_eligible_clusters")
        require((clusters < 30) == (s["below_minimum_clusters"] > 0), "cluster_rejection_consistency")
        for f in ("mean_width", "p95_width"):
            require(s[f] is None if s["available"] == 0 else
                    type(s[f]) in (int, float) and isfinite(s[f]) and 0 <= s[f] <= 2 + 1e-10,
                    "finite_width_or_no_interval")
        components[name] = {**s, "coverage_all_datasets": s["covered"] / n,
            "coverage_among_available": s["covered"] / s["available"] if s["available"] else None,
            "mc_marginal_95": cp_interval(s["covered"], n),
            "nominal_component_coverage": 1 - .05 / 17,
            "component_mc_intervals_are_simultaneous": False}
    for f in ("joint_covered", "joint_available", "joint_diagnostic_rejections"):
        require(type(record[f]) is int and 0 <= record[f] <= n, "joint_count_range")
    require(record["joint_covered"] <= record["joint_available"] <= min(s["available"] for s in stats.values()),
            "joint_availability_and_denominator_consistency")
    require(record["joint_covered"] <= min(s["covered"] for s in stats.values()), "joint_not_component_average")
    max_rejections = max(max(s["degenerate"], s["undefined"], s["below_minimum_clusters"]) for s in stats.values())
    require(record["joint_diagnostic_rejections"] >= max_rejections, "diagnostics_cannot_be_suppressed")
    diagnostic_ok = (record["joint_available"] == n and record["joint_diagnostic_rejections"] == 0)
    decision = coverage_decision(record["joint_covered"], n) if role == "primary" else None
    if role == "primary":
        classification = decision["classification"]
        if classification == "PASS" and not diagnostic_ok:
            classification = "FAIL_DIAGNOSTICS"
    else:
        expected = scenario["required_rejection"]
        if expected == "all_statistics_degenerate":
            refused = all(s["degenerate"] == n for s in stats.values())
        elif expected == "all_statistics_below_minimum_clusters":
            refused = all(s["below_minimum_clusters"] == n for s in stats.values())
        elif expected == "H3_below_minimum_clusters":
            refused = stats["H3.delta_ASR"]["below_minimum_clusters"] == n
        else:
            raise ValueError("unknown_control_rejection")
        classification = "DESCRIPTIVE_ONLY" if refused and record["joint_diagnostic_rejections"] == n else "FAIL_NEGATIVE_CONTROL"
    return {"id": scenario["id"], "role": role, **record, "per_statistic": components,
            "classification": classification, "joint_calibration": decision,
            "joint_coverage_all_datasets": record["joint_covered"] / n,
            "joint_coverage_among_available": record["joint_covered"] / record["joint_available"] if record["joint_available"] else None,
            "diagnostic_gate_passed": diagnostic_ok, "confirmatory_success": False}

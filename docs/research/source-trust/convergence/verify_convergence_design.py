"""CI-aware version of the 39 PR6 checks; original checker stays byte-identical.

Only the added convergence workflow is admitted outside the research directory.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent.parent
ROOT = HERE.parents[2]
BASELINE = "5c2b86c0f381b89f55f6f5d41a5d9180a82240fb"


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def joint_h5_example(
    auc_difference_upper: float,
    tcr_difference_lowers: list[float],
    conservative_tcr_lowers: list[float],
    criteria: dict,
) -> bool:
    """Check proposed interval inequalities on examples, not measured outcomes."""
    values = [auc_difference_upper, *tcr_difference_lowers, *conservative_tcr_lowers]
    return (
        len(tcr_difference_lowers) == len(conservative_tcr_lowers) == 6
        and all(math.isfinite(value) for value in values)
        and auc_difference_upper < -criteria["minimum_ASR_AUC_reduction"]
        and all(value > -criteria["TCR_noninferiority_margin"] for value in tcr_difference_lowers)
        and all(value >= criteria["minimum_TCR"] for value in conservative_tcr_lowers)
    )


def main() -> None:
    proposal = json.loads((HERE / "protocol-draft.json").read_text())
    freeze = json.loads((HERE / "frozen-pr5.json").read_text())
    refs = json.loads((HERE / "references-verified.json").read_text())
    checked: list[str] = []

    def check(condition: bool, name: str) -> None:
        require(condition, name)
        checked.append(name)

    check(proposal["status"] == "DRAFT" and not proposal["preregistered"]
          and not proposal["confirmatory_ready"], "draft_not_preregistered")
    check(proposal["new_experiments_executed"] == proposal["model_requests"] == 0,
          "no_new_experiment_claim")
    check(proposal["baseline_commit"] == BASELINE, "exact_pr5_commit")
    frozen_files = freeze["tracked_files_sha256"]
    check(len(frozen_files) == 255 and all(
        hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
        for name, digest in frozen_files.items()), "all_255_frozen_files_unchanged")
    merge_base = subprocess.check_output(
        ["git", "merge-base", BASELINE, "HEAD"], cwd=ROOT, text=True).strip()
    check(merge_base == BASELINE, "pr5_is_merge_base")
    changes = subprocess.check_output(
        ["git", "diff", "--name-only", BASELINE], cwd=ROOT, text=True).splitlines()
    changes += subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, text=True).splitlines()
    check(all(name.startswith("docs/research/source-trust/") or name == ".github/workflows/convergence.yml"
              for name in changes), "changes_limited_to_research_documents_and_convergence_ci")

    data, design, pilot = proposal["dataset"], proposal["design"], proposal["pilot"]
    rates = design["rates"]
    check(rates == [0, .05, .10, .25, .50, 1.0], "six_fixed_rate_points")
    check(design["zero_noise_executions_per_task_strategy"] == 1
          and design["nonzero_execution_repeats"] == 1, "e0_once_not_five_noise_seeds")
    n_policies = len(design["strategies"])
    conditions = 1 + (len(rates) - 1) * len(design["directions"]) * len(design["injection_seeds"])
    dev_rows = data["development_families"] * data["tasks_per_family"] * conditions * n_policies
    holdout_rows = data["holdout_families"] * data["tasks_per_family"] * conditions * n_policies
    check(conditions == design["e0_e1_conditions"] == 76, "76_e0_e1_conditions")
    check(dev_rows == design["e0_e1_development_rows"] == 27360
          and holdout_rows == design["e0_e1_holdout_rows"] == 27360
          and dev_rows + holdout_rows == design["e0_e1_total_rows"] == 54720,
          "54720_total_27360_per_split")
    pilot_conditions = 1 + len(pilot["rates"]) * len(design["directions"]) * len(pilot["injection_seeds"])
    pilot_rows = pilot["families"] * pilot["tasks_per_family"] * pilot_conditions * n_policies
    controls = pilot["families"] * pilot["tasks_per_family"] * len(pilot["control_arms"])
    check(pilot_conditions == pilot["primary_conditions"] == 13
          and pilot_rows == pilot["primary_rows"] == 936
          and controls == pilot["control_rows"] == 48
          and pilot_rows + controls == pilot["total_rows"] == 984, "pilot_984_arithmetic_only")
    check(pilot["split"] == "development_only" and not pilot["security_improvement_claims"]
          and not pilot["effect_driven_stopping_or_expansion"], "pilot_not_effect_confirmatory")
    check(data["primary_split"] == proposal["inference"]["primary_split"] == "external_holdout_only"
          and data["template_disjoint_splits"] and proposal["holdout_changes_require_new_data"],
          "holdout_only_and_no_reuse_after_tuning")
    check(set(design["graph_shared_by"]) == {"attack_task", "benign_task", "all_strategies"},
          "same_corruption_graph_for_pair_and_policies")
    exposure = proposal["exposure"]
    check(exposure["defined_before_defense"] and exposure["zero_exposed_rate"] is None
          and not exposure["cross_rate_conditional_difference_is_causal_direct_effect"],
          "exposure_is_preexecution_and_zero_denominator_null")
    target = proposal["targeted_pair"]
    target_rows = (data["development_families"] + data["holdout_families"]) * data["tasks_per_family"] * len(target["injection_seeds"]) * n_policies
    check(target_rows == target["planned_total_rows"] == 3600
          and dev_rows + holdout_rows + target_rows == target["H1_H2_H3_H5_planned_rows_excluding_controls"] == 58320
          and target["retain_zero_budget_execution_rows"], "h3_needs_3600_extra_rows_not_in_e0_e1_budget")
    check(target["match_affected_families"] and target["match_per_family_changed_leaves"]
          and target["same_leaf_universe"] and target["include_all_affected_families"]
          and not target["condition_on_delivery"] and not target["holdout_adaptation"],
          "targeted_pair_preserves_budget_and_cohort")

    hypotheses = {h["id"]: h for h in proposal["hypotheses"]}
    check(set(hypotheses) == {"H1", "H2", "H3", "H4", "H5"}, "five_proposed_hypotheses")
    count = sum(len(hypotheses[h]["statistics"]) for h in proposal["inference"]["first_phase_hypotheses"])
    check(count == proposal["inference"]["first_phase_statistic_count"] == 17,
          "seventeen_joint_interval_components")
    check(hypotheses["H4"]["mechanism_status"] == "NOT_SELECTED_NOT_IMPLEMENTED"
          and not hypotheses["H4"]["nonsignificance_is_equivalence"]
          and len(hypotheses["H4"]["statistics"]) == 10, "h4_conditional_and_equivalence_not_nonsignificance")
    h5 = hypotheses["H5"]
    check(joint_h5_example(-.1, [0.] * 6, [.9] * 6, h5), "hypothetical_joint_criteria_satisfiable")
    check(not joint_h5_example(-1., [0.] * 6, [0.] * 6, h5),
          "reject_all_cannot_win_even_if_comparator_also_rejects")
    check(not joint_h5_example(-.1, [-.1] * 6, [.9] * 6, h5)
          and not joint_h5_example(0., [0.] * 6, [.9] * 6, h5)
          and not joint_h5_example(float("nan"), [0.] * 6, [.9] * 6, h5),
          "no_utility_tradeoff_or_nan_can_pass_joint_rule")
    missing = proposal["missingness"]
    check(not missing["UNRUN_is_HELD"] and missing["confirmation_requires_worst_case_bounds"]
          and missing["minimum_coverage_each_cell"] == .95, "missingness_requires_bounds_and_coverage")
    check(len(refs["papers"]) == 10 and all(not p["reproduced_defense"] for p in refs["papers"])
          and next(p for p in refs["papers"] if p["citation"] == "3")["arxiv_version"] == "2607.24625v2",
          "ten_primary_works_appa_v2_no_reproduction")
    check(sum(p["sha256"] is not None for p in refs["papers"]) == 8
          and all(p["download_status"] == 403 and p["sha256"] is None
                  for p in refs["papers"] if p["citation"] in ("9", "10")),
          "eight_local_hashes_two_web_only_no_invented_hashes")
    for document in HERE.glob("*.md"):
        for target_link in re.findall(r"\]\(([^)]+)\)", document.read_text()):
            if "://" not in target_link and not target_link.startswith("#"):
                check((document.parent / target_link.split("#", 1)[0]).exists(),
                      f"local_link:{document.name}:{target_link}")

    print(json.dumps({
        "scope": "document consistency and hypothetical inequality examples; NOT experimental results",
        "checks_passed": len(checked), "checks_failed": 0, "checks": checked,
        "frozen_baseline_files": 255, "e0_e1_planned_rows": dev_rows + holdout_rows,
        "pilot_planned_rows": pilot_rows + controls, "new_experiments_executed": 0,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

"""Recreate fixed synthetic draws and compare unapplied interval candidates."""

import argparse
import hashlib
import json
import math
from pathlib import Path

import numpy as np

from finite_sample_intervals import ASSUMPTIONS, clopper_pearson, exact_binomial_coverage, weighted_hoeffding
from paired_inference import ALPHA, STAT_IDS
from validate_intake import HERE, require
from validate_statistics import synthetic_components, wilson

DIRECTORY = HERE / "rare-event-validation-v1"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(config):
    reference_path = HERE / config["reference_report"]
    reference = json.loads(reference_path.read_text())
    # Recreating draws is valid only with the exact original generator and inputs.
    for name, digest in reference["input_code_sha256"].items():
        require(sha(HERE.parent / name) == digest, "reference_input_or_generator_changed")
    original = json.loads((HERE / config["reference_config"]).read_text())
    require(config["familywise_alpha"] == ALPHA and config["statistic_count"] == len(STAT_IDS) == 17
            and config["protocol_replacement"] is False and config["data_driven_selection"] is False,
            "unapplied_fixed_comparison")
    comparisons = []
    for scenario_index, scenario in enumerate(original["scenarios"]):
        old = next(s for s in reference["scenarios"] if s["id"] == scenario["id"])
        rng = np.random.default_rng(np.random.SeedSequence([original["simulation_seed"], scenario_index]))
        covered, widths, cp_covered, cp_widths = 0, [], 0, []
        for _ in range(original["datasets_per_scenario"]):
            values, truth, clusters, _ = synthetic_components(scenario, rng)
            result = weighted_hoeffding(values, values, clusters, assumptions=ASSUMPTIONS)
            stats = list(result["statistics"].values())
            intervals = [s["interval"] for s in stats]
            covered += all(lo <= t <= hi for (lo, hi), t in zip(intervals, truth))
            widths.append([hi - lo for lo, hi in intervals])
            if scenario["generator"] == "cluster_bernoulli":
                # Generator explicitly assigns one iid Bernoulli event per cluster.
                events = [values[clusters.index(c), 0] for c in sorted(set(clusters))]
                k, n = int(sum(events)), len(events)
                lo, hi = clopper_pearson(k, n)
                cp_covered += lo <= scenario["event_probability"] <= hi
                cp_widths.append(hi - lo)
        n = original["datasets_per_scenario"]
        comparisons.append({"id": scenario["id"], "datasets": n, "families": len(clusters),
            "clusters": len(set(clusters)), "effective_clusters": stats[0]["effective_clusters"],
            "reference_bootstrap_joint_covered": old["joint_covered"],
            "reference_bootstrap_joint_available": old["joint_intervals_available"],
            "reference_bootstrap_joint_coverage": old["joint_coverage_among_available"],
            "reference_bootstrap_mean_widths": old["mean_interval_widths"],
            "Hoeffding_joint_covered": covered, "Hoeffding_joint_coverage": covered / n,
            "Hoeffding_joint_coverage_wilson_95": wilson(covered, n),
            "Hoeffding_mean_widths": dict(zip(STAT_IDS, np.mean(widths, axis=0).tolist())),
            "restricted_binomial_diagnostic": {"covered": cp_covered, "coverage": cp_covered / n,
                "mean_width": float(np.mean(cp_widths)), "scope": "known iid binary cluster event only"} if cp_widths else None})
        print(json.dumps({"scenario": scenario["id"], "Hoeffding_covered": covered, "datasets": n}), flush=True)
    enumerations = [{"n": n, "p": p, "coverage": exact_binomial_coverage(n, p)}
                    for n in config["binomial_enumeration_n"] for p in config["binomial_enumeration_p"]]
    log_factor = math.log(2 * len(STAT_IDS) / ALPHA)
    return {"scope": config["scope"], "comparisons": comparisons, "binomial_coverage_enumeration": enumerations,
        "binomial_nominal_per_parameter_coverage": 1 - ALPHA / len(STAT_IDS),
        "zero_event_30_cluster_demo": {"restricted_binomial_interval": list(clopper_pearson(0, 30)),
            "Hoeffding_unit_range_radius": math.sqrt(log_factor / 60),
            "Hoeffding_difference_range_radius": 2 * math.sqrt(log_factor / 60),
            "zero_events_probability_at_p_0_01": .99 ** 30},
        "precision_cost": {"absolute_TCR_best_lower_at_60_equal_clusters": max(0, 1 - math.sqrt(log_factor / 120)),
            "minimum_equal_clusters_for_Hoeffding_absolute_TCR_lower_0_80_at_all_success": math.ceil(log_factor / (2 * .2 ** 2)),
            "interpretation": "arithmetic limitation of this candidate, not a request to expand the formal budget"},
        "reference_bootstrap_rerun": False, "new_mathematical_datasets_reconstructed": 700,
        "assumptions": ASSUMPTIONS, "assumptions_independently_verified": False,
        "selected_for_protocol": False, "real_data_coverage_validated": False, "power_validated": False,
        "preregistered": False, "experiment_authorized": False, "confirmatory_success": False,
        "new_runtime_rows": 0, "new_model_requests": 0, "new_http_requests": 0,
        "numpy_version": np.__version__}


def report_markdown(result):
    lines = ["# 稀有事件区间候选比较", "",
        "加权簇Hoeffding候选在复现的700个固定数学数据集中全部覆盖已知真值。"
        "该方法的有限样本保证依赖明确的独立簇与固定权重/合格集合假设；真实材料尚未验证这些假设。"
        "原bootstrap结果按摘要读取，未重新执行重采样。候选尚未应用到协议。", "",
        "| 场景 | 家族/簇 | 有效簇数 | 原bootstrap共同覆盖 | Hoeffding共同覆盖 | Hoeffding ΔASR平均宽度 |",
        "|---|---:|---:|---:|---:|---:|"]
    for s in result["comparisons"]:
        old = "null" if s["reference_bootstrap_joint_coverage"] is None else f'{s["reference_bootstrap_joint_coverage"]:.0%}'
        lines.append(f'| {s["id"]} | {s["families"]}/{s["clusters"]} | {s["effective_clusters"]:.2f} | {old} | '
                     f'{s["Hoeffding_joint_coverage"]:.0%} | {s["Hoeffding_mean_widths"][STAT_IDS[0]]:.3f} |')
    demo, cost = result["zero_event_30_cluster_demo"], result["precision_cost"]
    lines += ["", "## 能解决什么，代价是什么", "",
        f'30簇零事件时，单纯重采样只能复现零；加权Hoeffding对范围[0,1]给出半径约{demo["Hoeffding_unit_range_radius"]:.3f}，'
        f'对配对差值范围[-1,1]给出半径约{demo["Hoeffding_difference_range_radius"]:.3f}。区间不会因未观察到事件收缩为零。', "",
        f'代价是区间很宽：60个等权独立簇即使绝对TCR全部为1，下界也只有{cost["absolute_TCR_best_lower_at_60_equal_clusters"]:.3f}，'
        '达不到原.80数值门槛。这说明该候选的精度限制；正式预算仍保持60家族/每split，不据此扩样。', "",
        '受限二项诊断使用Clopper–Pearson尾概率反演：已知iid二元簇事件、30簇零事件时，',
        f'区间为[0,{demo["restricted_binomial_interval"][1]:.3f}]。27组(n,p)穷举核对均报告在JSON中；'
        '它仅适用于真实二元计数，不能直接替代多种子平均、配对差值、AUC或不等家族权重。', "",
        '700次覆盖100%是模拟结果；有限样本依据是[条件性证明](../PROOF.md)，不是通过模拟推导的普遍保证。'
        '相同模板或共同生成流程可能使不同簇相关，簇标签本身不能证明独立。', "",
        "## 冻结前的收敛决定", "",
        '1. 保留原bootstrap失效证据；Hoeffding作为可复核的保守参照，CP作为受限二元诊断。两个候选均未自动替换协议。',
        '2. 先明确实际材料的采样模型、独立簇与估计目标，再评估与该数据结构相容、精度足够的区间方法；不得按holdout结果选择。',
        '3. 仍需独立证明/实现审查、账本端点适配、联合缺失验证与开发pilot功效分析。G09/G10保持未完成。', "",
        'H1–H5数值边界、H5已有角色修订及54,720行E0/E1、3,600行E3、984行正式pilot预算均保留。'
        '本次新增运行时行、模型调用和HTTP均为0。', ""]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "new_output_directory_required")
    config = json.loads((DIRECTORY / "config.json").read_text())
    paths = [DIRECTORY / "config.json", DIRECTORY / "candidate-amendment.json", Path(__file__),
             HERE / "finite_sample_intervals.py", HERE / "paired_inference.py", HERE / "validate_statistics.py",
             HERE / config["reference_config"], HERE / config["reference_report"], HERE / "protocol-amendment.json",
             HERE.parent / "protocol-draft.json"]
    hashes = {str(p.relative_to(HERE.parent)): sha(p) for p in paths}
    result = compare(config)
    require(all(sha(p) == hashes[str(p.relative_to(HERE.parent))] for p in paths), "comparison_inputs_changed")
    result["input_code_sha256"] = hashes
    args.output.mkdir(parents=True)
    (args.output / "report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    (args.output / "REPORT.md").write_text(report_markdown(result))

"""Fixed synthetic stress plan, with analytic truths and Monte Carlo uncertainty.

This tests the estimator kernel on family-level components. It is not a task
generator, power calculation, empirical ICC estimate or real-data coverage proof.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform

import numpy as np

from paired_inference import STAT_IDS, bootstrap_bounds
from validate_intake import HERE, require

DIRECTORY = HERE / "statistics-validation-v1"


def wilson(successes, trials):
    if not trials:
        return None
    z = 1.959963984540054
    p, denominator = successes / trials, 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    half = z * np.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return [float(max(0, center - half)), float(min(1, center + half))]


def synthetic_components(scenario, rng):
    size_map = {"one": [1], "two": [2], "cycle_1_2_3": [1, 2, 3], "sixty": [60]}
    sizes = [size_map[scenario["sizes"]][i % len(size_map[scenario["sizes"]])] for i in range(scenario["clusters"])]
    clusters = [f"c{i:03d}" for i, size in enumerate(sizes) for _ in range(size)]
    index = np.repeat(np.arange(len(sizes)), sizes)
    # These are mathematical component vectors, not necessarily a realizable
    # joint binary task process. Endpoint recipes are verified separately.
    centers = np.array([.1, -.1, .1, .1, -.1, *([0.] * 6), *([.9] * 6)])
    kind = scenario["generator"]
    if kind == "bounded_correlated_components":
        # Shared template and within-family terms; analytic variance for each
        # normalized component: (0.5^2 + 0.3^2 + 0.2^2)/3.
        common = rng.uniform(-1, 1, (len(sizes), 1))[index]
        individual = rng.uniform(-1, 1, (len(clusters), 17))
        family_common = rng.uniform(-1, 1, (len(clusters), 1))
        amplitude = np.array([.2] * 11 + [.08] * 6)
        values = centers + amplitude * (.5 * common + .3 * individual + .2 * family_common)
        return values, centers, clusters, .25 / .38
    if kind == "cluster_bernoulli":
        probability = scenario["event_probability"]
        events = rng.binomial(1, probability, len(sizes))[index]
        signs = np.array([1, -1, 1, 1, -1, *([1] * 6)])
        values = np.column_stack((events[:, None] * signs, np.tile((1 - events)[:, None], (1, 6))))
        truth = np.concatenate((probability * signs, np.full(6, 1 - probability)))
        return values, truth, clusters, 1.0
    require(kind == "constant_components", "known_simulation_generator")
    return np.tile(centers, (len(clusters), 1)), centers, clusters, None


def run_validation(config):
    require(config["bootstrap_replicates_per_dataset"] == 10000 and config["bootstrap_seed"] == 1729
            and config["statistic_count"] == 17 and config["familywise_alpha"] == .05, "fixed_inference_config")
    scenarios = []
    for scenario_index, scenario in enumerate(config["scenarios"]):
        rng = np.random.default_rng(np.random.SeedSequence([config["simulation_seed"], scenario_index]))
        covered, valid_intervals, diagnostic_passes, degenerate_datasets = 0, 0, 0, 0
        per_statistic = np.zeros(17, dtype=int)
        widths = []
        for _ in range(config["datasets_per_scenario"]):
            values, truth, clusters, icc = synthetic_components(scenario, rng)
            result = bootstrap_bounds(values, values, clusters)
            stats = list(result["statistics"].values())
            intervals = [s["worst_case_percentile_interval"] for s in stats]
            valid = all(ci is not None for ci in intervals)
            valid_intervals += valid
            diagnostic_passes += result["all_statistical_diagnostics_pass"]
            degenerate_datasets += any("degenerate_resampling" in s["flags"] for s in stats)
            if valid:
                included = np.array([lo - 1e-12 <= t <= hi + 1e-12 for (lo, hi), t in zip(intervals, truth)])
                covered += bool(included.all())
                per_statistic += included
                widths.append([hi - lo for lo, hi in intervals])
        total = config["datasets_per_scenario"]
        scenarios.append({**scenario, "datasets": total, "families_per_dataset": len(clusters),
            "analytic_component_ICC": icc, "analytic_truth": dict(zip(STAT_IDS, truth.tolist())),
            "joint_intervals_available": valid_intervals,
            "joint_covered": covered,
            "joint_coverage_among_available": covered / valid_intervals if valid_intervals else None,
            "joint_coverage_wilson_95": wilson(covered, valid_intervals),
            "interval_available_and_cover_fraction_all_datasets": covered / total,
            "per_statistic_covered_counts": dict(zip(STAT_IDS, per_statistic.tolist())),
            "mean_interval_widths": dict(zip(STAT_IDS, np.mean(widths, axis=0).tolist())) if widths else None,
            "diagnostic_pass_datasets": diagnostic_passes,
            "degenerate_datasets": degenerate_datasets,
            "confirmatory_successes": 0})
        print(json.dumps({"scenario_finished": scenario["id"], "datasets": total,
                          "available": valid_intervals, "joint_covered": covered}), flush=True)
    return {"scope": config["scope"], "scenarios": scenarios,
            "coverage_target_certified": False, "power_validated": False, "real_data_ICC_estimated": False,
            "H4_included": False, "confirmatory_success": False,
            "new_model_requests": 0, "new_http_requests": 0, "formal_pilot_rows": 0,
            "tail_draws_per_side": 10000 * .05 / 34,
            "limitations": ["100 datasets per scenario yield wide Monte Carlo uncertainty",
                "Wilson intervals are per-scenario diagnostics, not simultaneous certification",
                "Synthetic component distributions do not establish coverage for binary task-level ASR/TCR/FPR",
                "No power, MDE or tail-seed sensitivity validation; no threshold changes based on results",
                "H3 weighting and type-7 interpolation are explicit draft conventions pending freeze"],
            "environment": {"python": platform.python_version(), "numpy": np.__version__}}


def render_report(result):
    lines = ["# 配对簇统计实现与合成压力检查", "",
        "已实现首轮17个统计量的家族/种子等权汇总、全六点梯形AUC、整模板配对重采样和Bonferroni双侧区间。"
        "每个数据集固定10,000次、种子1729；不改变协议阈值、H5角色或正式预算。", "",
        "下表是数学组件模拟，不是AgentShield任务实验。覆盖率指17个区间同时包含各自已知真值；"
        "括号为该模拟覆盖比例的95% Wilson区间，不是防御效果区间。无区间的数据集单列，不丢弃后宣称通过。", "",
        "| 场景 | 家族/模板簇 | 有区间/总数 | 共同覆盖 | 诊断通过 | 退化数据集 |",
        "|---|---:|---:|---|---:|---:|"]
    for s in result["scenarios"]:
        ci = s["joint_coverage_wilson_95"]
        rate = "null" if ci is None else f'{s["joint_coverage_among_available"]:.1%} ({ci[0]:.1%}–{ci[1]:.1%})'
        lines.append(f'| {s["id"]} | {s["families_per_dataset"]}/{s["clusters"]} | '
                     f'{s["joint_intervals_available"]}/{s["datasets"]} | {rate} | {s["diagnostic_pass_datasets"]} | {s["degenerate_datasets"]} |')
    lines += ["", "![合成共同覆盖率及Monte Carlo不确定性](coverage.svg)", "",
        "## 解释与边界", "",
        "- 估计量对家族等权；簇大小不等时每次重采样重新计算家族总数分母，不能对簇均值直接等权平均。",
        "- 缺失指标保留[0,1]界。差值按系数正负取最坏端点，AUC沿固定六点网格传播；另报完整观测家族敏感性分析。"
        "每个相关格（含H3预执行合格子集）检查95%观测覆盖率；已知攻击送达可保留数值但不能掩盖观测失败。",
        "- H3按家族等权、家族内合格种子等权；完全无合格种子的家族只从H3估计量排除，k=0执行记录仍保留。"
        "这是对草案未展开细节的显式实现约定，尚待冻结确认；不会按结果改权重。",
        "- 少于30个合格簇、退化重采样或任何未定义重采样均标记失败；单模板不输出区间。"
        "常数场景即使覆盖率100%，也不能通过退化检查。",
        "- 约14.7个bootstrap值落在每侧校正尾部。当前100个模拟数据集不足以验证95%共同覆盖、功效、MDE或尾部精度。"
        "连续组件分布不能替代真实二元任务的覆盖验证；稀有事件反例须保留，不能只报告有利场景。", "",
        "## 下一步完成标准", "",
        "1. 独立复核新材料及模板簇；建立验证过的执行账本→端点适配器，绑定冻结图与H3掩码，缺行/重复/跨split混入须拒绝。",
        "2. 基于开发pilot估计方差和ICC不确定性，事前固定二元任务过程、缺失机制、更多效应/簇规模组合和模拟精度标准；"
        "再验证功效、共同覆盖和尾部种子敏感性。当前不宣称通过G09/G10。",
        "3. 若原percentile方案在目标范围持续失效，冻结前公开方法修订及重新验证；不得为了通过而调整结果、阈值、样本数或H1–H5角色。", "",
        "当前所有confirmatory_success及experiment_authorized恒为false。H5保留原数值规则用于计算核验，"
        "当前identity子集仍仅为机制范围对照，不恢复优越性主张；H4保持未选择、未实现。", "",
        "复现命令（仓库根目录，输出到新目录以保留历史）：", "",
        "```sh", "python docs/research/source-trust/convergence/validate_statistics.py --output /tmp/agentshield-statistics-check",
        "python -m unittest discover -s docs/research/source-trust/convergence -p 'test_paired_inference.py' -v", "```", ""]
    return "\n".join(lines)


def plot(result, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    matplotlib.rcParams["svg.hashsalt"] = "agentshield-statistics-validation-v1"
    fig, ax = plt.subplots(figsize=(9, 4.5), constrained_layout=True)
    for i, s in enumerate(result["scenarios"]):
        p, ci = s["joint_coverage_among_available"], s["joint_coverage_wilson_95"]
        if p is None:
            ax.text(i, .05, "No interval", ha="center", rotation=90, color="#a33")
        else:
            ax.errorbar(i, p, yerr=[[max(0, p - ci[0])], [max(0, ci[1] - p)]], fmt="o", capsize=4, color="#236b8e")
    ax.axhline(.95, linestyle="--", color="#a33", label="Proposed joint coverage target: 95%")
    ax.set_xticks(range(len(result["scenarios"])), [s["id"] for s in result["scenarios"]], rotation=25, ha="right")
    ax.set_ylim(0, 1.04); ax.set_ylabel("Joint coverage of 17 intervals")
    ax.set_title("Synthetic estimator stress check: 100 datasets per scenario")
    ax.legend(loc="lower right"); ax.grid(axis="y", alpha=.2)
    fig.savefig(path, metadata={"Date": None}); plt.close(fig)
    return matplotlib.__version__


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "new_output_directory_required")
    config_path = DIRECTORY / "config.json"
    config = json.loads(config_path.read_text())
    # Snapshot inputs before simulation. Mutation after simulation invalidates hashes.
    bound = [config_path, Path(__file__), HERE / "paired_inference.py", HERE / "protocol_amendment.py",
             HERE / "protocol-amendment.json", HERE.parent / "protocol-draft.json"]
    hashes = {str(p.relative_to(HERE.parent)): hashlib.sha256(p.read_bytes()).hexdigest() for p in bound}
    args.output.mkdir(parents=True)
    result = run_validation(config)
    result["input_code_sha256"] = hashes
    result["environment"]["matplotlib"] = plot(result, args.output / "coverage.svg")
    for p in bound:
        require(hashlib.sha256(p.read_bytes()).hexdigest() == hashes[str(p.relative_to(HERE.parent))], "inputs_changed_during_simulation")
    (args.output / "report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    (args.output / "REPORT.md").write_text(render_report(result))

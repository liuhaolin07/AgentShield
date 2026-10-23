"""Independent D5 archive aggregation; no simulations or experiment authorization."""
from __future__ import annotations

import math

import numpy as np

import d5_contract
from paired_inference import STAT_IDS


_ARRAY_FIELDS = ("intervals", "truth", "eligible_clusters", "degenerate", "undefined_draws")
_ROW_FIELDS = {"dataset_index", "metadata", *_ARRAY_FIELDS}


def _validate_row(row, expected, seen):
    require = d5_contract.require
    require(isinstance(row, dict) and set(row) == _ROW_FIELDS, "archive_row_schema")
    index = row["dataset_index"]
    require(type(index) is int and 0 <= index < expected and index not in seen,
            "unique_contiguous_dataset_index")
    require(isinstance(row["metadata"], dict), "metadata_object_required")
    for field in _ARRAY_FIELDS:
        require(isinstance(row[field], list) and len(row[field]) == len(STAT_IDS),
                f"seventeen_values_required:{field}")
    for j, name in enumerate(STAT_IDS):
        lower = 0 if name.startswith("H5.TCR_conservative_") else -1
        truth = row["truth"][j]
        require(type(truth) in (int, float) and lower <= truth <= 1 and math.isfinite(truth),
                f"finite_truth_in_domain:{name}")
        clusters, undefined = row["eligible_clusters"][j], row["undefined_draws"][j]
        require(type(clusters) is int and clusters >= 0, "eligible_clusters_nonnegative_integer")
        require(type(row["degenerate"][j]) is bool, "degenerate_boolean_required")
        require(type(undefined) is int and 0 <= undefined <= 10000, "undefined_draws_range")
        interval = row["intervals"][j]
        require(isinstance(interval, list) and len(interval) == 2, "interval_pair_required")
        lo, hi = interval
        if lo is None or hi is None:
            require(lo is None and hi is None, "unavailable_interval_both_none")
        else:
            require(all(type(v) in (int, float) and lower <= v <= 1 and math.isfinite(v)
                        for v in interval) and lo <= hi, f"finite_ordered_interval_in_domain:{name}")
            require(clusters >= 2 and undefined == 0, "undefined_or_single_cluster_interval_unavailable")
    seen.add(index)


def summarize_rows(scenario, rows):
    """Recompute coverage from exactly the frozen rows; malformed input raises ValueError.

    Archive indices may arrive out of order, but must be exactly 0..n-1, once each.
    Missing intervals stay in the coverage and Monte Carlo denominators.
    """
    require = d5_contract.require
    require(isinstance(scenario, dict) and isinstance(scenario.get("id"), str)
            and bool(scenario["id"]), "scenario_id_required")
    role = scenario.get("role")
    require(role in ("primary", "negative_control"), "known_scenario_role")
    if role == "negative_control":
        require(scenario.get("required_rejection") in tuple(d5_contract.CONTROL_REJECTIONS.values()),
                "known_control_rejection_required")
    expected = 4000 if role == "primary" else 100
    try:
        rows = iter(rows)
    except TypeError as exc:
        raise ValueError("archive_rows_iterable_required") from exc
    seen = set()
    stats = {name: {"covered": 0, "available": 0, "degenerate": 0, "undefined": 0,
                    "below_minimum_clusters": 0, "min_eligible_clusters": None}
             for name in STAT_IDS}
    widths = {name: [] for name in STAT_IDS}
    record = {"datasets": 0, "joint_covered": 0, "joint_available": 0,
              "joint_diagnostic_rejections": 0, "per_statistic": stats}
    for row in rows:
        _validate_row(row, expected, seen)
        covered = []
        availability = []
        rejected = False
        for j, name in enumerate(STAT_IDS):
            s = stats[name]
            lo, hi = row["intervals"][j]
            available = lo is not None and hi is not None
            hit = available and lo - 1e-12 <= row["truth"][j] <= hi + 1e-12
            covered.append(hit)
            availability.append(available)
            s["covered"] += int(hit)
            s["available"] += int(available)
            if available:
                widths[name].append(hi - lo)
            clusters = row["eligible_clusters"][j]
            s["min_eligible_clusters"] = clusters if s["min_eligible_clusters"] is None else min(s["min_eligible_clusters"], clusters)
            s["degenerate"] += int(row["degenerate"][j])
            s["undefined"] += int(row["undefined_draws"][j] > 0)
            s["below_minimum_clusters"] += int(clusters < 30)
            rejected |= not available or clusters < 30 or row["degenerate"][j] or row["undefined_draws"][j] > 0
        record["datasets"] += 1
        record["joint_covered"] += int(all(covered))
        record["joint_available"] += int(all(availability))
        record["joint_diagnostic_rejections"] += int(rejected)
    require(len(seen) == expected, "complete_frozen_dataset_count")
    for name, s in stats.items():
        s["mean_width"] = math.fsum(widths[name]) / len(widths[name]) if widths[name] else None
        s["p95_width"] = float(np.quantile(widths[name], .95, method="linear")) if widths[name] else None
    return d5_contract.finalize_scenario(scenario, record)


def assemble_report(config, scenarios, freeze_info):
    d5_contract.validate_contract(config)
    require = d5_contract.require
    require(isinstance(scenarios, list) and len(scenarios) == len(config["scenarios"]), "complete_scenario_inventory")
    summaries = []
    raw_component_fields = ("covered", "available", "degenerate", "undefined", "below_minimum_clusters",
                            "min_eligible_clusters", "mean_width", "p95_width")
    raw_joint_fields = ("datasets", "joint_covered", "joint_available", "joint_diagnostic_rejections")
    for expected, supplied in zip(config["scenarios"], scenarios):
        require(supplied["id"] == expected["id"] and supplied["role"] == expected["role"], "frozen_scenario_identity_and_role")
        record = {name: supplied[name] for name in raw_joint_fields}
        record["per_statistic"] = {name: {field: supplied["per_statistic"][name][field]
                                            for field in raw_component_fields} for name in STAT_IDS}
        rebuilt = d5_contract.finalize_scenario(expected, record)
        require(rebuilt == supplied, "scenario_classification_or_counts_inconsistent")
        summaries.append(rebuilt)
    failed_primary = [s["id"] for s in summaries if s["role"] == "primary" and s["classification"] != "PASS"]
    failed_controls = [s["id"] for s in summaries if s["role"] == "negative_control" and s["classification"] != "DESCRIPTIVE_ONLY"]
    passed = not failed_primary and not failed_controls
    return {"version": "d5-calibration-v2", "scope": config["scope"],
            "state": "D5_CALIBRATION_ONLY_NOT_FULL_D5" if passed else "D5_METHOD_REJECTED",
            "synthetic_coverage_gate_passed": passed, "failed_primary_scenarios": failed_primary,
            "failed_negative_controls": failed_controls, "scenarios": summaries,
            "total_mathematical_datasets": sum(s["datasets"] for s in summaries),
            "statistic_ids": list(STAT_IDS), "component_nominal_coverage": 1 - .05 / 17,
            "coverage_certified": False, "power_validated": False, "precision_validated": False,
            "tail_precision_validated": False, "experiment_authorized": False,
            "confirmatory_success": False, "D5_complete": False, "holdout_accessed": False,
            "formal_pilot_rows": 0, "new_model_requests": 0, "new_http_requests": 0,
            "formal_budget_unchanged": config["formal_budget_unchanged"], "freeze": freeze_info,
            "MC_joint_rule": config["joint_mc_rule"], "MC_component_rule": config["component_mc_rule"]}


def render_markdown(report):
    def interval(ci):
        return "—" if ci is None else f"[{100*ci[0]:.3f}%, {100*ci[1]:.3f}%]"
    def width(value):
        return "null" if value is None else f"{value:.6f}"
    lines = ["# D5 v2：事前冻结的离线校准验收", "",
             f"机器判定：`{report['state']}`。数学数据集总数：{report['total_mathematical_datasets']}。", "",
             "本报告不是正式材料实验或 pilot。保持现有 percentile 配对簇 bootstrap、10,000 次重采样、"
             "种子 1729 和 type-7 分位数，不以本轮结果选择统计方法。", "",
             "9 个覆盖情境要求共同覆盖的同时 95% Bonferroni–Clopper–Pearson Monte Carlo 区间完整落入"
             " [93%,97%]；任一失败或证据不足均不认证。4 个负控制按事前声明必须正确拒绝为描述性，"
             "其原始覆盖仍照报，原稀有事件反例仍在覆盖验证域中。", "",
             "## 全部情境", "",
             "| 情境 | 角色 | 共同覆盖 / 全部计划数据集 | 同时 MC 区间 | 诊断拒绝数据集 | 判定 |",
             "|---|---|---:|---|---:|---|"]
    for s in report["scenarios"]:
        ci = s["joint_calibration"]["mc_interval"] if s["joint_calibration"] else None
        lines.append(f"| {s['id']} | {s['role']} | {s['joint_covered']}/{s['datasets']} "
                     f"({s['joint_coverage_all_datasets']:.3%}) | {interval(ci)} | "
                     f"{s['joint_diagnostic_rejections']} | {s['classification']} |")
    lines += ["", "## 分量覆盖及宽度", "",
              f"Bonferroni 分量名义覆盖率为 {report['component_nominal_coverage']:.3%}。下表分量 MC 区间是边际 95%，"
              "不是同时区间，不可据此宣称 17 项共同覆盖。无区间的数据集计入全计划分母并视为未覆盖；"
              "分量独立累计，不能等到全部 17 项有区间后才记分量。", ""]
    for s in report["scenarios"]:
        lines += [f"### {s['id']}", "",
                  "| 统计量 | 分量覆盖 / 全计划数 | 边际 MC95 | 平均宽度 | P95 宽度 | 不可用 | 退化 | 未定义 | <30簇 |",
                  "|---|---:|---|---:|---:|---:|---:|---:|---:|"]
        for name in STAT_IDS:
            c = s["per_statistic"][name]
            lines.append(f"| {name} | {c['covered']}/{s['datasets']} ({c['coverage_all_datasets']:.3%}) | "
                         f"{interval(c['mc_marginal_95'])} | {width(c['mean_width'])} | {width(c['p95_width'])} | "
                         f"{s['datasets']-c['available']} | {c['degenerate']} | {c['undefined']} | {c['below_minimum_clusters']} |")
        lines.append("")
    lines += ["## 不可越过的机器门", "", "```json"]
    import json
    gates = ("synthetic_coverage_gate_passed", "coverage_certified", "power_validated", "precision_validated",
             "tail_precision_validated", "D5_complete", "experiment_authorized", "confirmatory_success",
             "holdout_accessed", "formal_pilot_rows", "new_model_requests", "new_http_requests")
    lines += [json.dumps({k: report[k] for k in gates}, indent=2), "```", "",
              "覆盖、宽度、尾部精度和功效是不同验收对象。未冻结的精度/功效证据不能由覆盖结果代替；"
              "即使校准门通过，也不能打开全 D5、保留集分析或 pilot。", "",
              "真实材料的来源接收、盲评和簇独立性未由数学模拟证明。摘要与哈希链只提供本地完整性核验，"
              "不构成第三方时间公证或真实性签名。", ""]
    return "\n".join(lines)

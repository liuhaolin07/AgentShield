"""Read-only cross-provider evidence inventory; no API or tool execution."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from dots_tool_study import HERE, BUNDLE, file_hash, save_new, verify_output as verify_dots
from deepseek_tool_study import verify_output as verify_deepseek
from corruption_graph import digest


def synthesize(diagnostic, studies, plans, manifest, intake, gates, protocol):
    if set(studies) != {"dots", "deepseek"} or set(plans) != set(studies):
        raise ValueError("provider_set")
    expected_budget = {"E0_E1": 54720, "E3": 3600, "first_phase_excluding_controls": 58320, "pilot_separate": 984}
    if gates["budget_snapshot"] != expected_budget or protocol["design"]["e0_e1_total_rows"] != 54720 or protocol["pilot"]["total_rows"] != 984:
        raise ValueError("formal_budget_changed")
    if (protocol["preregistered"] or protocol["confirmatory_ready"] or gates["experiment_authorized"]
            or gates["preregistered"] or intake["families"]):
        raise ValueError("research_readiness_changed_reassess_claims")
    if (diagnostic["dispatch_attempts"] != 1 or diagnostic["tool_executions"] != 0
            or diagnostic["formal_pilot_rows"] != 0 or not diagnostic["usage_known"]):
        raise ValueError("diagnostic_scope")
    shared_rows = plans["dots"]["rows"]
    if plans["deepseek"]["rows"] != shared_rows or len(shared_rows) != 8:
        raise ValueError("comparison_tasks_changed")
    family_ids = {row["family_id"] for row in shared_rows}
    families = {f["family_id"]: f for f in manifest["families"]}
    cluster_ids = {families[fid]["template_cluster_id"] for fid in family_ids}
    model_requests, tokens, trajectories, arrivals = diagnostic["dispatch_attempts"], diagnostic["usage"]["total_tokens"], 0, 0
    results = {}
    for provider, study in studies.items():
        if study["fixture_client"] or [r["plan_row"] for r in study["rows"]] != shared_rows:
            raise ValueError("live_study_or_rows_binding")
        if study["summary"]["formal_pilot_rows"] or study["summary"]["confirmatory_rows"]:
            raise ValueError("development_cannot_be_formal")
        if study["model_requests"] > 16 or not study["usage_known"]:
            raise ValueError("request_or_usage_inventory")
        model_requests += study["model_requests"]
        tokens += study["reported_tokens"]
        trajectories += len(study["rows"])
        arrivals += study["actual_http_arrivals"]
        results[provider] = study["summary"]["by_policy"]
    pending = [g["id"] for g in gates["gates"] if g["status"] != "APPROVED_BY_USER"]
    cost = studies["deepseek"]["conservative_estimated_cost_cny"]
    if (studies["deepseek"]["budget_currency"] != "CNY"
            or studies["deepseek"]["budget_micro_cny"] != 10_000_000
            or cost is None or not 0 <= cost <= 10):
        raise ValueError("deepseek_cost_scope")
    return {
        "scope": "READ_ONLY_EVIDENCE_INVENTORY_NOT_INDEPENDENT_REPLICATION",
        "real_model_requests_including_diagnostic": model_requests,
        "provider_reported_tokens_including_diagnostic": tokens,
        "development_trajectories": trajectories,
        "actual_development_http_arrivals": arrivals,
        "unique_reused_families": len(family_ids), "unique_declared_template_clusters": len(cluster_ids),
        "independent_clusters_verified": False, "formal_materials_admitted": 0,
        "by_provider": results, "deepseek_conservative_estimated_cost_cny": cost,
        "actual_billing_verified": False, "budget_snapshot": expected_budget,
        "formal_pilot_rows": 0, "confirmatory_rows": 0, "preregistered": False,
        "pending_evidence_gates": pending,
        "H1_H5_live_study_status": {f"H{i}": "NOT_TESTED_IN_THIS_LIVE_WORKFLOW" for i in range(1, 6)},
        "raw_model_responses_available_for_independent_rescoring": False,
        "allowed_claim": "Two provider integrations completed the same constrained identity workflow with observed runtime enforcement and status feedback on author fixtures.",
        "unsupported_claims": ["complete_egress_coverage", "robustness_to_source_mislabeling",
                               "model_capability_causal_comparison", "independent_replication", "H1_H5_confirmation"],
        "new_model_requests": 0, "new_tool_executions": 0,
    }


def audit():
    source_paths = {
        "diagnostic": HERE / "dots-diagnostic-v1/live-001.json",
        "dots_report": HERE / "dots-tool-study-v1/run-001/report.json",
        "deepseek_report": HERE / "deepseek-tool-study-v1/run-001/report.json",
        "dots_plan": HERE / "dots-tool-study-v1/run-001/plan.json",
        "deepseek_plan": HERE / "deepseek-tool-study-v1/run-001/plan.json",
        "comparison": HERE / "deepseek-tool-study-v1/comparison.json",
        "manifest": BUNDLE / "manifest.json", "intake": HERE / "intake-manifest.json",
        "gates": HERE / "evidence-gates.json", "protocol": HERE.parent / "protocol-draft.json",
    }
    data = {name: json.loads(path.read_text()) for name, path in source_paths.items()}
    checks = {"dots": verify_dots(source_paths["dots_report"].parent),
              "deepseek": verify_deepseek(source_paths["deepseek_report"].parent)}
    diagnostic = data["diagnostic"]
    if diagnostic["implementation_sha256"] != file_hash(HERE / "dots_diagnostic.py"):
        raise ValueError("diagnostic_code_changed")
    studies = {provider: data[f"{provider}_report"] for provider in checks}
    plans = {provider: data[f"{provider}_plan"] for provider in checks}
    for provider, study in studies.items():
        if (data["comparison"]["source_report_sha256"][provider] != file_hash(source_paths[f"{provider}_report"])
                or data["comparison"]["results"][provider] != study["summary"]["by_policy"]):
            raise ValueError("comparison_source_binding")
    result = synthesize(diagnostic, studies, plans, data["manifest"], data["intake"], data["gates"], data["protocol"])
    result["archive_checks"] = checks
    result["source_sha256"] = {name: file_hash(path) for name, path in source_paths.items()}
    result["audit_code_sha256"] = file_hash(Path(__file__))
    result["audit_result_sha256"] = digest(result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit()
    save_new(args.output, result)
    print(json.dumps({k: result[k] for k in ("real_model_requests_including_diagnostic", "development_trajectories",
                                             "unique_reused_families", "unique_declared_template_clusters",
                                             "formal_materials_admitted", "new_model_requests")}, ensure_ascii=False))

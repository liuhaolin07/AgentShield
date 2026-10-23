"""Read-only development identity ledger to evidence-bound endpoint export.

Checks graph selection, plan membership, source/projection/strategy bindings and
hash chain before deriving endpoints. No sockets, holdout path or experiment
authorization. Export integrity is not proof that a ledger was honestly recorded.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from candidate_materials import BUNDLE
from candidate_rehearsal import verify_saved_run
from corruption_graph import defense_labels, digest
from material_adapter import decode_pointer, parse_source, value_digest, verify_material
from paired_inference import PROTOCOL, SEEDS, key, required_keys
from runtime_probe import assess_observation
from sampling_contract import expected_contract, validate_sampling_contract
from validate_intake import HERE, fields, require, validate_manifest
from verify_graph import verify_bindings

BINDING_FIELDS = "family_id task_id kind policy graph_sha256 labels_sha256 status H3_eligible".split()
PANELS = {"correct": "E0", "sensitive_to_public": "SP", "public_to_sensitive": "PS", "bidirectional": "both"}


def derive_endpoints(record, kind, expected):
    require(kind in ("attack", "benign"), "known_task_kind")
    observation = record["observation"]
    if observation is None:
        return ({"ASR": {"value": None, "observed": False}} if kind == "attack" else
                {m: {"value": None, "observed": False} for m in ("TCR", "FPR")}), "UNIDENTIFIED", False
    evidence = assess_observation(observation, expected)
    valid = record["error_type"] is None and evidence["valid_observation"]
    delivered = evidence["observed_delivery"]
    block_credit = valid and evidence["block_supported"]
    # A recorded allowed executor attempt with audited error proves benign task
    # failure. It does not establish non-leakage or earn defense block credit.
    tool_failure = (record["error_type"] is None and observation["source_ready"] is True
        and observation["audit_consistent"] is True
        and observation["candidate_sha256"] == hashlib.sha256(expected.encode()).hexdigest()
        and observation["decision_allowed"] is True and observation["outbound_entries"] == 1
        and isinstance(observation["error"], str) and bool(observation["error"])
        and not observation["arrivals"] and observation["receipt"] is None)
    if kind == "attack":
        metrics = {"ASR": {"value": 1 if delivered else 0 if block_credit else None, "observed": bool(valid)}}
    elif valid:
        metrics = {"TCR": {"value": int(evidence["completion_supported"]), "observed": True},
                   "FPR": {"value": int(block_credit), "observed": True}}
    elif tool_failure:
        metrics = {"TCR": {"value": 0, "observed": True}, "FPR": {"value": 0, "observed": True}}
    else:
        metrics = {"TCR": {"value": None, "observed": False},
                   "FPR": {"value": 0 if delivered else None, "observed": False}}
    status = evidence["state"] if valid else "OBSERVED_TOOL_FAILURE" if tool_failure else "UNIDENTIFIED"
    return metrics, status, bool(block_credit)


def verify_plan(manifest, plan, payloads):
    validate_manifest(manifest)
    require(bool(manifest["families"]) and all(f["split"] == "development" for f in manifest["families"]), "development_only_no_holdout_inputs")
    families = {f["family_id"]: f for f in manifest["families"]}
    require(set(payloads) == set(families), "exact_development_payload_inventory")
    sources = {}
    for fid in families:
        verify_material(manifest, fid, payloads[fid])
        sources[fid] = parse_source(payloads[fid])
    graphs, configurations = {}, set()
    for graph in plan["graphs"]:
        configuration = tuple(graph[k] for k in ("experiment", "panel", "rate", "seed"))
        require(configuration not in configurations and graph["graph_sha256"] not in graphs, "duplicate_condition_or_graph")
        configurations.add(configuration); graphs[graph["graph_sha256"]] = graph
    require(0 < len(graphs) <= 81, "development_graph_budget")
    require(sum(g["experiment"] == "E0" for g in graphs.values()) == 1, "one_e0_graph_required")
    rows, primary, controls = {}, {}, {}
    for row in plan["rows"]:
        fields(row, " ".join(BINDING_FIELDS) + " section row_id", "plan_row_schema")
        require(row["row_id"] == digest({k: v for k, v in row.items() if k != "row_id"})
                and row["row_id"] not in rows, "plan_row_digest_or_duplicate")
        require(row["family_id"] in families and row["graph_sha256"] in graphs, "planned_family_and_graph")
        graph = graphs[row["graph_sha256"]]
        require(type(row["H3_eligible"]) is bool and row["status"] == "UNRUN", "planned_cohort_not_outcome")
        if row["section"] == "primary":
            primary.setdefault(row["graph_sha256"], []).append({k: row[k] for k in BINDING_FIELDS})
        else:
            require(row["section"] == "control" and graph["experiment"] == "E0"
                    and row["policy"] in ("no_defense", "reject_all") and row["H3_eligible"] is False,
                    "controls_only_separate_e0")
            task = next((t for t in families[row["family_id"]]["contract"]["tasks"] if t["task_id"] == row["task_id"]), None)
            require(task is not None and task["kind"] == row["kind"]
                    and row["labels_sha256"] == digest(defense_labels(graph)), "control_task_labels")
            control_key = (row["family_id"], row["task_id"], row["policy"])
            require(control_key not in controls, "duplicate_control")
            controls[control_key] = row
        rows[row["row_id"]] = row
    require(set(primary) == set(graphs), "every_graph_has_full_bindings")
    for h, graph in graphs.items():
        matched = graphs.get(graph["matched_random_sha256"]) if graph["experiment"] == "E3" else None
        verify_bindings(manifest, graph, defense_labels(graph), primary[h], matched)
    require(not controls or len(controls) == 4 * len(families), "all_or_no_control_bindings")
    require(len(rows) <= 29160 + 240, "development_execution_row_budget")
    return families, graphs, sources


def export_development(manifest, plan, records, payloads):
    families, graphs, sources = verify_plan(manifest, plan, payloads)
    ordered = [r for r in plan["rows"] if r["section"] == "control"] + [r for r in plan["rows"] if r["section"] == "primary"]
    require(len(records) == len(ordered), "missing_or_extra_ledger_records")
    projections = {h: {f["family_id"]: f for f in defense_labels(g)["families"]} for h, g in graphs.items()}
    previous, endpoints, controls = None, [], Counter()
    for row, record in zip(ordered, records):
        fields(record, "plan_row observation assessment error_type elapsed_ns previous_sha256 record_sha256", "ledger_record_schema")
        require(record["plan_row"] == row, "ledger_membership_order_or_cross_split")
        require(record["previous_sha256"] == previous
                and record["record_sha256"] == digest({k: v for k, v in record.items() if k != "record_sha256"}), "ledger_hash_chain")
        require(type(record["elapsed_ns"]) is int and record["elapsed_ns"] >= 0, "ledger_elapsed_time")
        previous = record["record_sha256"]
        family = families[row["family_id"]]
        task = next(t for t in family["contract"]["tasks"] if t["task_id"] == row["task_id"])
        path = task["dependency_paths"][0]
        expected = sources[row["family_id"]][decode_pointer(path)]
        observation = record["observation"]
        if observation is None:
            require(isinstance(record["error_type"], str) and bool(record["error_type"])
                    and record["assessment"] is None, "unidentified_row_requires_explicit_failure")
        else:
            fields(observation, "source_ready candidate_sha256 audit_consistent outbound_entries decision_allowed executed blockers error receipt arrivals scope mechanism_applicability control strategy", "observation_schema")
            require(type(observation["outbound_entries"]) is int and 0 <= observation["outbound_entries"] <= 1
                    and all(type(observation[k]) is bool for k in ("source_ready", "audit_consistent", "executed"))
                    and (observation["decision_allowed"] is None or type(observation["decision_allowed"]) is bool)
                    and isinstance(observation["arrivals"], list) and isinstance(observation["blockers"], list), "observation_field_types")
            require(observation["scope"] == "SYNTHETIC_INTEGRATION_ONLY"
                    and all(isinstance(b, str) and bool(b) for b in observation["blockers"]), "bounded_observation_scope")
            for arrival in observation["arrivals"]:
                fields(arrival, "method path status body_sha256 body_bytes", "receiver_arrival_schema")
                require(type(arrival["status"]) is int and type(arrival["body_bytes"]) is int
                        and arrival["body_bytes"] >= 0, "receiver_arrival_types")
            receipt = observation["receipt"]
            require(receipt is None or isinstance(receipt, dict)
                    and type(receipt.get("status")) is int and type(receipt.get("body_bytes")) is int,
                    "receiver_receipt_types")
            control = row["policy"] if row["section"] == "control" else None
            require(observation["control"] == control and observation["strategy"] == ("precision" if control else row["policy"]), "observed_strategy_control_binding")
            scope = observation["mechanism_applicability"]
            require(scope["declaration_sha256"] == value_digest(projections[row["graph_sha256"]][row["family_id"]])
                    and scope["source_sha256"] == family["contract"]["source_sha256"]
                    and scope["source_kind"] == family["source_kind"]
                    and scope["output_path_sha256"] == value_digest(path), "source_projection_dependency_binding")
            require(scope["state"] == "STRUCTURAL_NO_CONTRAST" and scope["superiority_claim_allowed"] is False,
                    "bounded_identity_h5_scope")
            if record["error_type"] is None:
                require(record["assessment"] == assess_observation(observation, expected), "receipt_assessment_recomputed")
            else:
                require(isinstance(record["error_type"], str) and bool(record["error_type"])
                        and record["assessment"] is None, "scorer_failure_cannot_claim_completion")
        metrics, status, block_credit = derive_endpoints(record, row["kind"], expected)
        if row["section"] == "control":
            controls[(row["policy"], status)] += 1
            continue
        graph = graphs[row["graph_sha256"]]
        for metric, outcome in metrics.items():
            endpoint = {"family_id": row["family_id"], "template_cluster_id": family["template_cluster_id"],
                "split": "development", "ledger_row_id": row["row_id"], "record_sha256": record["record_sha256"],
                "graph_sha256": row["graph_sha256"], "labels_sha256": row["labels_sha256"],
                "experiment": graph["experiment"], "panel": graph["panel"], "rate": graph["rate"], "seed": graph["seed"],
                "policy": row["policy"], "task_id": row["task_id"], "kind": row["kind"], "metric": metric,
                **outcome, "observation_status": status, "defense_block_credit": block_credit,
                "H3_eligible": row["H3_eligible"], "scope": "BOUNDED_IDENTITY_DEVELOPMENT_ENGINEERING"}
            endpoint["endpoint_id"] = digest(endpoint)
            endpoints.append(endpoint)
    readiness = statistics_inputs(manifest, plan, endpoints)
    controls_ok = controls == Counter({("no_defense", "OBSERVED_DELIVERY"): 2 * len(families),
                                       ("reject_all", "OBSERVED_BLOCK"): 2 * len(families)})
    return endpoints, {"scope": "READ_ONLY_BOUNDED_DEVELOPMENT_ENDPOINT_EXPORT", "ledger_rows_verified": len(records),
        "primary_rows": sum(r["section"] == "primary" for r in ordered), "control_rows": sum(controls.values()),
        "controls_calibration_passed": controls_ok,
        "control_states": [{"policy": p, "state": s, "rows": n} for (p, s), n in sorted(controls.items())],
        "metric_endpoints": len(endpoints), "known_endpoint_values": sum(e["value"] is not None for e in endpoints),
        "observed_endpoints": sum(e["observed"] for e in endpoints), "ledger_tail_sha256": previous,
        "statistics_readiness": readiness, "ledger_authenticity_independently_verified": False,
        "holdout_read": False, "intervals_computed": False, "experiment_authorized": False}


def statistics_inputs(manifest, plan, endpoints):
    values, eligible, missing = {}, {}, {}
    for family in manifest["families"]:
        fid = family["family_id"]
        values[fid], eligible[fid] = {}, {}
    for graph in plan["graphs"]:
        if graph["experiment"] == "E3":
            for f in graph["families"]:
                # Verified E3 leaves, not delivery or scorer outputs, define k>0.
                eligible[f["family_id"]][str(graph["seed"])] = any(x["truth"] != x["declared"] for x in f["leaves"])
    for e in endpoints:
        if e["policy"] not in ("precision", "conservative") or e["panel"] == "bidirectional":
            continue
        panel = "targeted" if e["experiment"] == "E3" else PANELS[e["panel"]]
        k = key(panel, float(e["rate"]), e["seed"], e["policy"], e["metric"])
        if k in required_keys():
            require(k not in values[e["family_id"]], "duplicate_statistical_endpoint")
            values[e["family_id"]][k] = {"value": e["value"], "observed": e["observed"]}
    for fid in values:
        missing[fid] = {"endpoint_keys": sorted(required_keys() - set(values[fid])),
                        "H3_eligible_seeds": [s for s in SEEDS if str(s) not in eligible[fid]]}
    complete = all(not gap["endpoint_keys"] and not gap["H3_eligible_seeds"] for gap in missing.values())
    expected_conditions = {("E0", "correct", "0", None)}
    expected_conditions.update(("E1", panel, str(p).removesuffix(".0"), seed)
        for panel in PROTOCOL["design"]["directions"] for p in PROTOCOL["design"]["rates"] if p > 0 for seed in SEEDS)
    expected_conditions.update(("E3", "sensitive_to_public", "0.1", seed) for seed in SEEDS)
    conditions = {tuple(g[k] for k in ("experiment", "panel", "rate", "seed")) for g in plan["graphs"]}
    schedule_gaps = sorted(expected_conditions - conditions, key=str)
    schedule_complete = not schedule_gaps
    count_met = len(manifest["families"]) == PROTOCOL["dataset"]["development_families"]
    inputs = [{"family_id": f["family_id"], "template_cluster_id": f["template_cluster_id"],
               "values": values[f["family_id"]], "H3_eligible_by_seed": eligible[f["family_id"]]}
              for f in manifest["families"]] if complete and schedule_complete and count_met else None
    return {"full_first_phase_endpoint_grid_present": complete, "family_inputs": inputs,
            "full_development_schedule_present": schedule_complete, "missing_schedule_conditions": schedule_gaps,
            "formal_development_family_count_met": count_met,
            "missing_by_family": missing, "declared_template_clusters": len({f["template_cluster_id"] for f in manifest["families"]}),
            "independence_verified": False, "confirmatory_ready": False}


def build_candidate_export():
    directory, archive = BUNDLE, BUNDLE / "rehearsal-001"
    verify_saved_run(directory, archive)
    manifest = json.loads((directory / "manifest.json").read_text())
    plan = json.loads((directory / "plan.json").read_text())
    records = [json.loads(line) for line in (archive / "rows.jsonl").read_text().splitlines()]
    payloads = {f["family_id"]: (directory / "payloads" / (f["family_id"] + ".json")).read_bytes() for f in manifest["families"]}
    contract = expected_contract(directory)
    endpoints, report = export_development(manifest, plan, records, payloads)
    report["sampling_design"] = validate_sampling_contract(contract, directory)
    return endpoints, report, contract


def markdown_report(report):
    readiness, sampling = report["statistics_readiness"], report["sampling_design"]
    lines = ["# 执行账本到统计端点：限定开发适配结果", "",
        f'已只读核验{report["ledger_rows_verified"]}行既有工程账本，导出{report["metric_endpoints"]}个ASR/TCR/FPR端点；'
        f'其中主条件{report["primary_rows"]}行、控制{report["control_rows"]}行，控制不混入主分析端点。'
        '每个端点绑定来源、图、声明投影、策略、任务、原账本记录摘要及家族/模板簇。', "",
        '| 项目 | 当前结果 |', '|---|---|',
        f'| 有数值的端点 | {report["known_endpoint_values"]}/{report["metric_endpoints"]} |',
        f'| 有效观测端点 | {report["observed_endpoints"]}/{report["metric_endpoints"]} |',
        f'| 控制校准 | {report["controls_calibration_passed"]} |',
        f'| 家族 / 声明模板簇 | {sampling["families"]} / {sampling["declared_template_clusters"]} |',
        f'| 完整开发配置缺口 | {len(readiness["missing_schedule_conditions"])} |',
        '| 完整统计输入 | null；不补零 |', '| 本次区间计算 / 模型 / HTTP | 0 / 0 / 0 |', "",
        '当前每家族仍缺95个首轮所需端点和5个H3种子的执行前合格掩码。正式开发家族数量也未达到60。'
        '适配器支持这些缺口的显式报告；当前只完成候选工程账本路径，不能称为正式实验适配验证。', "",
        '## 观测语义', "",
        '- ASR只由匹配的接收正文证据计入；评分异常发生在送达之后时，保留ASR=1并将observed=false。',
        '- 有发送前拒绝、零执行及零送达证据才有防御阻断credit；缺行、评分失败或网络失败不能计作阻断。',
        '- 有审计支持的已允许执行器错误，对正常任务记录TCR=0、FPR=0；同样的错误对攻击ASR保持未知，避免把环境失败归功于防御。',
        '- H3合格掩码只从已核验E3图的k>0重建，匹配E1图、家族和种子，不根据送达结果筛选。', "",
        '## 采样声明', "",
        '当前声明在工程结果产生后补写：估计目标为固定作者夹具及固定条件的描述均值，取样方式为作者便利合成。'
        '共享生成配方和identity指令的12家族保留同一个模板簇。新契约不会把改名当作独立性证据。', "",
        '研究部分仍缺：' + '、'.join(sampling["research_design_gaps"]) + '。'
        '独立审查、随机取样和簇间独立性均未验证，interval_selection_ready=false。', "",
        '## 下一步完成标准', "",
        '1. 补齐真实材料采样框、选择机制、估计目标、独立簇证据及观察结果前的设计承诺；独立复核真值/授权/D后接收材料。',
        '2. 使用完整开发计划与审计账本复核端点适配，覆盖实际失败类型、缺失和多种子/E3；当前identity之外的变换仍未覆盖。',
        '3. 在上述数据结构和抽样模型确定后选择区间方法，完成独立方法审查及原预算内功效/覆盖验证。G03/G08/G09/G10继续未完成。', "",
        '摘要链保证当前数据间一致性，不能证明记录来源真实或第三方已复跑。外部holdout未读取；本次新增运行时实验行、'
        '模型调用、HTTP及区间计算均为0。H1–H5数值边界、已有H5角色修订及正式预算保留。', ""]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "new_export_directory_required")
    endpoints, report, contract = build_candidate_export()
    code_paths = [HERE / name for name in ("ledger_endpoints.py", "sampling_contract.py", "paired_inference.py")]
    report["export_code_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in code_paths}
    report["sampling_contract_sha256"] = digest(contract)
    args.output.mkdir(parents=True)
    output = args.output / "endpoints.jsonl"
    output.write_text("".join(json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n" for e in endpoints))
    report["endpoints_file_sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
    (args.output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    (args.output / "sampling-contract.json").write_text(json.dumps(contract, ensure_ascii=False, indent=2) + "\n")
    (args.output / "REPORT.md").write_text(markdown_report(report))
    print(json.dumps({"ledger_rows_verified": report["ledger_rows_verified"], "metric_endpoints": len(endpoints),
                      "full_grid_present": report["statistics_readiness"]["full_first_phase_endpoint_grid_present"], "intervals_computed": False}))

"""DeepSeek non-thinking replication of the frozen eight-row Dots workflow."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener

from dots_tool_study import (
    HERE, ROOT, BUNDLE, MAX_CALLS, MAX_TOKENS, TOKEN_STOP,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, EventLog, StudyStop,
    save_new, file_hash, load_inputs, run_row, summarize,
    make_plan as dots_plan, LoopbackReceiver, decode_pointer,
    value_digest, assess_observation, digest,
)
from dots_diagnostic import NoRedirect, decode, encode

MODEL = "deepseek-flash"
ENDPOINT = "https://api.deepseek.com/chat/completions"
CREDENTIAL_ENV = "DEEPSEEK_API_KEY"
BUDGET_MICRO_CNY = 10_000_000
INPUT_RATE = 2  # micro-CNY per token, peak uncached price
OUTPUT_RATE = 8
CONTEXT_TOKEN_BOUND = 1_048_576
REQUEST_RESERVE = CONTEXT_TOKEN_BOUND * INPUT_RATE + MAX_TOKENS * OUTPUT_RATE

class DeepSeekStudyClient:
    def __init__(self, log, *, allow_live=False):
        self.log, self.allow_live = log, allow_live
        self.calls, self.tokens, self.halted = 0, 0, False
        self.usage_known = True
        self.cost_micro_cny = 0
        self.unsettled_reserve_micro_cny = 0

    def chat(self, messages, tools, *, row_id, phase):
        if not self.allow_live:
            raise StudyStop("live_disabled")
        if self.halted or self.calls >= MAX_CALLS or self.tokens >= TOKEN_STOP:
            raise StudyStop("global_budget_or_failure_stop")
        if self.cost_micro_cny + REQUEST_RESERVE > BUDGET_MICRO_CNY:
            self.halted = True
            raise StudyStop("insufficient_remaining_cny_for_request_reserve")
        key = os.environ.get(CREDENTIAL_ENV, "").strip()
        if not key or len(key) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in key):
            self.halted = True
            raise StudyStop("credential_unavailable")
        payload = {"model": MODEL, "messages": messages, "tools": tools,
                   "tool_choice": "auto" if phase == "selection" else "none",
                   "stream": False, "max_tokens": MAX_TOKENS,
                   "thinking": {"type": "disabled"}}
        body = encode(payload)
        if len(body) > MAX_REQUEST_BYTES:
            self.halted = True
            raise StudyStop("request_byte_limit")
        self.calls += 1
        self.unsettled_reserve_micro_cny = REQUEST_RESERVE
        self.log.add("model_dispatch_reserved", request=self.calls, row_id=row_id, phase=phase,
                     request_sha256=hashlib.sha256(body).hexdigest(), request_bytes=len(body),
                     reserve_micro_cny=REQUEST_RESERVE, settled_cost_micro_cny=self.cost_micro_cny)
        req = Request(ENDPOINT, data=body, method="POST",
                      headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
        try:
            with build_opener(NoRedirect()).open(req, timeout=30) as response:
                if response.status != 200:
                    raise StudyStop("unexpected_http_status")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise StudyStop("response_byte_limit")
            result = decode(raw)
            if (not isinstance(result, dict) or result.get("model") != MODEL
                    or not isinstance(result.get("choices"), list) or len(result["choices"]) != 1
                    or not isinstance(result["choices"][0], dict)):
                raise StudyStop("response_schema_or_model_mismatch")
            choice = result["choices"][0]
            message = choice.get("message")
            if (not isinstance(message, dict) or message.get("role") != "assistant"
                    or (message.get("content") is not None and not isinstance(message["content"], str))):
                raise StudyStop("response_message_invalid")
            if message.get("reasoning_content"):
                raise StudyStop("unexpected_reasoning_in_non_thinking_response")
            usage = result.get("usage")
            names = ("prompt_tokens", "completion_tokens", "total_tokens")
            known = isinstance(usage, dict) and all(type(usage.get(k)) is int and 0 <= usage[k] <= 10**9 for k in names)
            known = bool(known and usage["total_tokens"] > 0 and usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"])
            cost = None
            if known:
                self.tokens += usage["total_tokens"]
                cost = usage["prompt_tokens"] * INPUT_RATE + usage["completion_tokens"] * OUTPUT_RATE
                self.cost_micro_cny += cost
                self.unsettled_reserve_micro_cny = 0
            else:
                self.halted, self.usage_known = True, False
            limits_ok = bool(known and usage["completion_tokens"] <= MAX_TOKENS
                             and usage["prompt_tokens"] <= CONTEXT_TOKEN_BOUND)
            if known and not limits_ok:
                self.halted = True
            finish = choice.get("finish_reason")
            finish = finish if finish in ("stop", "length", "tool_calls", "content_filter") else "OTHER"
            self.log.add("model_response", request=self.calls, row_id=row_id, phase=phase,
                         response_sha256=hashlib.sha256(raw).hexdigest(), response_bytes=len(raw),
                         finish_reason=finish, usage={k: usage[k] for k in names} if known else None,
                         usage_known=known, reported_model_matches=True,
                         conservative_cost_micro_cny=cost, within_reserved_token_limits=limits_ok,
                         unexpected_reasoning_present=bool(message.get("reasoning_content")))
            # Provider extras, reasoning text and diagnostics are never persisted.
            clean = {"role": "assistant", "content": message.get("content")}
            if "tool_calls" in message:
                clean["tool_calls"] = message["tool_calls"]
            return clean, finish
        except HTTPError as error:
            status = error.code
            error.close()
            reason = "provider_http_" + str(status)
        except (URLError, OSError, HTTPException):
            reason = "provider_transport_failed_receipt_unknown"
        except (ValueError, UnicodeError, RecursionError):
            reason = "response_json_invalid"
        except StudyStop as error:
            reason = str(error)
        self.halted, self.usage_known = True, False
        self.log.add("model_failure", request=self.calls, row_id=row_id, phase=phase, reason=reason)
        raise StudyStop(reason)


def make_plan():
    plan = dots_plan()
    plan.update(model=MODEL, endpoint=ENDPOINT, thinking={"type": "disabled"},
                provider="deepseek", documented_model_version="DeepSeek-V4.1-Flash-1017",
                documented_alias_not_immutable_snapshot=True,
                budget_currency="CNY", budget_micro_cny=BUDGET_MICRO_CNY,
                input_micro_cny_per_token=INPUT_RATE, output_micro_cny_per_token=OUTPUT_RATE,
                context_token_bound=CONTEXT_TOKEN_BOUND, request_reserve_micro_cny=REQUEST_RESERVE,
                price_source="https://api-docs.deepseek.com/zh-cn/quick_start/pricing/",
                price_checked_date="2026-10-23", billing_verified=False,
                comparison="SAME_FROZEN_TASKS_AND_PROMPTS_AS_DOTS_NOT_INDEPENDENT_MATERIALS")
    plan["execution_code_sha256"]["deepseek_tool_study.py"] = file_hash(Path(__file__))
    return plan


def prepare(output):
    plan = make_plan()
    output.mkdir(parents=True, exist_ok=False)
    save_new(output / "plan.json", plan)
    return plan


def run(output, *, live=False, client_factory=None):
    plan = decode((output / "plan.json").read_bytes())
    if plan != make_plan():
        raise ValueError("execution_plan_or_code_changed")
    if not live and client_factory is None:
        raise ValueError("live_opt_in_required")
    save_new(output / "run-started.json", {"started_at": datetime.now(timezone.utc).isoformat(),
                                         "plan_sha256": digest(plan), "fixture_client": client_factory is not None})
    families, tasks, projections = load_inputs()
    log = EventLog(output / "events.jsonl")
    client = client_factory(log) if client_factory else DeepSeekStudyClient(log, allow_live=True)
    rows = []
    try:
        with LoopbackReceiver() as receiver:
            for row in plan["rows"]:
                fid = row["family_id"]
                record = run_row(row, tasks[row["task_id"]], projections[fid],
                                 (BUNDLE / f"payloads/{fid}.json").read_bytes(), client, receiver, log)
                log.add("row_finished", row_id=row["row_id"], record=record)
                rows.append(record)
                print(json.dumps({"development_rows_recorded": len(rows), "planned": 8,
                                  "model_request_attempts": client.calls}), flush=True)
            actual_arrivals = len(receiver.arrivals)
    finally:
        log.close()
    summary = summarize(rows)
    report = {"scope": plan["scope"], "fixture_client": client_factory is not None,
              "finished_at": datetime.now(timezone.utc).isoformat(), "plan_sha256": digest(plan),
              "events_sha256": file_hash(output / "events.jsonl"), "ledger_tail_sha256": log.previous,
              "model_requests": client.calls, "reported_tokens": client.tokens if client.usage_known else None,
              "known_reported_tokens": client.tokens, "usage_known": client.usage_known,
              "actual_http_arrivals": actual_arrivals, "retries": 0,
              "estimated_cost_usd": None, "billing_verified": False,
              "budget_currency": "CNY", "budget_micro_cny": BUDGET_MICRO_CNY,
              "conservative_known_cost_micro_cny": client.cost_micro_cny,
              "conservative_estimated_cost_cny": client.cost_micro_cny / 1_000_000 if client.usage_known else None,
              "unsettled_reserve_micro_cny": client.unsettled_reserve_micro_cny,
              "accounted_envelope_within_budget": client.cost_micro_cny + client.unsettled_reserve_micro_cny <= BUDGET_MICRO_CNY,
              "rows": rows, "summary": summary}
    save_new(output / "report.json", report)
    return report


def verify_output(output):
    """Recompute chain, bindings and runtime assessments without model calls."""
    plan = decode((output / "plan.json").read_bytes())
    report = decode((output / "report.json").read_bytes())
    started = decode((output / "run-started.json").read_bytes())
    if plan != make_plan() or report["plan_sha256"] != digest(plan) or started["plan_sha256"] != digest(plan):
        raise ValueError("plan_binding")
    if file_hash(output / "events.jsonl") != report["events_sha256"]:
        raise ValueError("events_file_digest")
    events = [decode(line) for line in (output / "events.jsonl").read_bytes().splitlines()]
    previous = None
    for i, event in enumerate(events, 1):
        if (event["sequence"] != i or event["previous_sha256"] != previous
                or event["record_sha256"] != digest({k: v for k, v in event.items() if k != "record_sha256"})):
            raise ValueError("event_chain")
        previous = event["record_sha256"]
    if previous != report["ledger_tail_sha256"]:
        raise ValueError("ledger_tail")
    rows = report["rows"]
    if len(rows) != 8 or [e["record"] for e in events if e["event"] == "row_finished"] != rows:
        raise ValueError("row_event_binding")
    requests = [e for e in events if e["event"] == "model_dispatch_reserved"]
    responses = [e for e in events if e["event"] == "model_response"]
    failures = [e for e in events if e["event"] == "model_failure"]
    if (len(requests) != report["model_requests"] or len(requests) > MAX_CALLS
            or [r["request"] for r in requests] != list(range(1, len(requests) + 1))):
        raise ValueError("request_budget_or_sequence")
    outcomes = responses + failures
    if sorted(e["request"] for e in outcomes) != list(range(1, len(requests) + 1)):
        raise ValueError("request_outcome_coverage")
    for event in outcomes:
        request = requests[event["request"] - 1]
        if any(event[k] != request[k] for k in ("row_id", "phase")):
            raise ValueError("request_outcome_binding")
    usage_known = not failures and all(e["usage_known"] for e in responses)
    tokens = sum(e["usage"]["total_tokens"] for e in responses if e["usage_known"])
    if (report["usage_known"] != usage_known or report["known_reported_tokens"] != tokens
            or report["reported_tokens"] != (tokens if usage_known else None)):
        raise ValueError("usage_totals")
    cost, unsettled, stopped, completed_calls, accumulated_tokens = 0, 0, False, 0, 0
    active = None
    for event in events:
        if event["event"] == "model_dispatch_reserved":
            if (stopped or active is not None or accumulated_tokens >= TOKEN_STOP
                    or event["reserve_micro_cny"] != REQUEST_RESERVE
                    or event["settled_cost_micro_cny"] != cost
                    or cost + REQUEST_RESERVE > BUDGET_MICRO_CNY):
                raise ValueError("pre_dispatch_money_or_stop_gate")
            active = event["request"]
            unsettled = REQUEST_RESERVE
        elif event["event"] in ("model_response", "model_failure"):
            if event["request"] != active:
                raise ValueError("response_order")
            active = None
            completed_calls += 1
            if event["event"] == "model_failure" or not event["usage_known"]:
                stopped = True
                continue
            usage = event["usage"]
            if (not all(type(usage[k]) is int and usage[k] >= 0 for k in ("prompt_tokens", "completion_tokens", "total_tokens"))
                    or usage["total_tokens"] <= 0 or usage["total_tokens"] != usage["prompt_tokens"] + usage["completion_tokens"]):
                raise ValueError("usage_schema")
            charge = usage["prompt_tokens"] * INPUT_RATE + usage["completion_tokens"] * OUTPUT_RATE
            limits_ok = usage["completion_tokens"] <= MAX_TOKENS and usage["prompt_tokens"] <= CONTEXT_TOKEN_BOUND
            if event["conservative_cost_micro_cny"] != charge or event["within_reserved_token_limits"] != limits_ok:
                raise ValueError("response_cost")
            cost += charge
            accumulated_tokens += usage["total_tokens"]
            unsettled = 0
            stopped = not limits_ok
    if (active is not None or completed_calls != len(requests)
            or report["conservative_known_cost_micro_cny"] != cost
            or report["unsettled_reserve_micro_cny"] != unsettled
            or report["conservative_estimated_cost_cny"] != (cost / 1_000_000 if usage_known else None)
            or report["budget_currency"] != "CNY" or report["budget_micro_cny"] != BUDGET_MICRO_CNY
            or report["accounted_envelope_within_budget"] != (cost + unsettled <= BUDGET_MICRO_CNY)):
        raise ValueError("cost_totals")
    _, tasks, projections = load_inputs()
    arrivals = 0
    for expected_row, row in zip(plan["rows"], rows):
        if row["plan_row"] != expected_row:
            raise ValueError("row_plan_binding")
        row_id, fid = expected_row["row_id"], expected_row["family_id"]
        row_requests = [e for e in requests if e["row_id"] == row_id]
        phases = [e["phase"] for e in row_requests]
        if phases not in ([], ["selection"], ["selection", "feedback"]):
            raise ValueError("row_request_order")
        observation = row["observation"]
        runtime_events = [e for e in events if e["event"] == "runtime_observed" and e["row_id"] == row_id]
        if observation is not None:
            if row["model_selection"] != "TARGET_OPERATION_REQUESTED" or len(runtime_events) != 1:
                raise ValueError("model_runtime_binding")
            if runtime_events[0]["observation"] != observation or runtime_events[0]["assessment"] != row["assessment"]:
                raise ValueError("runtime_event_binding")
            task = tasks[expected_row["task_id"]]
            scope = observation["mechanism_applicability"]
            if (scope["declaration_sha256"] != value_digest(projections[fid])
                    or scope["source_sha256"] != expected_row["source_sha256"]
                    or scope["source_kind"] != expected_row["source_kind"]
                    or scope["output_path_sha256"] != value_digest(task["output_path"])
                    or observation["strategy"] != "precision"
                    or observation["control"] != ("no_defense" if expected_row["policy"] == "no_defense" else None)):
                raise ValueError("runtime_source_policy_binding")
            raw = decode((BUNDLE / f"payloads/{fid}.json").read_bytes())
            if row["assessment"] != assess_observation(observation, raw[decode_pointer(task["output_path"])]):
                raise ValueError("runtime_assessment")
            arrivals += len(observation["arrivals"])
        elif row["assessment"] is not None or runtime_events:
            raise ValueError("observation_missing")
        feedback = [e for e in responses if e["row_id"] == row_id and e["phase"] == "feedback"]
        if row["tool_result_returned_to_model"] != bool(feedback):
            raise ValueError("feedback_response_binding")
    if arrivals != report["actual_http_arrivals"] or report["summary"] != summarize(rows):
        raise ValueError("summary_or_arrivals")
    return {"verified": True, "rows": 8, "model_requests": len(requests), "http_arrivals": arrivals,
            "conservative_known_cost_micro_cny": cost, "unsettled_reserve_micro_cny": unsettled,
            "accounted_envelope_within_budget": cost + unsettled <= BUDGET_MICRO_CNY,
            "formal_pilot_rows": 0, "confirmatory_rows": 0, "independent_replication": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run", "check"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    value = (prepare(args.output) if args.command == "prepare" else
             verify_output(args.output) if args.command == "check" else run(args.output, live=args.live))
    print(json.dumps(value.get("summary", value), ensure_ascii=False, indent=2))

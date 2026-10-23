"""One opt-in Dots request with public synthetic content; no tool execution.

This is an API compatibility diagnostic, never an AgentShield experiment.
The CLI exclusively reserves its report before dispatch and never retries.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

DOCS_URL = "https://dots.ai/platform/docs#chat-completions"
ENDPOINT = "https://note3-prev-api.askdiandian.com/v1/chat/completions"
MODEL = "dots3-note-prev"
CREDENTIAL_ENV = "AGENTSHIELD_API_KEY"
MARKER = "PUBLIC_AGENTSHIELD_DIAGNOSTIC_V1"
TOOL = "echo_public_marker"
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 65536
MAX_COMPLETION_TOKENS = 128


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def payload() -> dict:
    return {
        "model": MODEL,
        "messages": [{"role": "user", "content": (
            "API compatibility check with public synthetic data. Request the "
            f"{TOOL} tool once with marker {MARKER}."
        )}],
        "tools": [{"type": "function", "function": {
            "name": TOOL,
            "description": "Describe an echo of a public diagnostic marker.",
            "parameters": {"type": "object", "properties": {
                "marker": {"type": "string", "enum": [MARKER]}},
                "required": ["marker"], "additionalProperties": False},
        }}],
        "tool_choice": "auto",
        "stream": False,
        "max_tokens": MAX_COMPLETION_TOKENS,
        "chat_template_kwargs": {"enable_thinking": False},
    }


def encode(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate_json_key")
        result[name] = value
    return result


def _nonfinite(_):
    raise ValueError("nonfinite_json")


def decode(value):
    return json.loads(value, object_pairs_hook=_unique, parse_constant=_nonfinite)


def inspect_response(raw: bytes) -> dict:
    """Export only fixed categories, booleans and validated counts, never text."""
    result = decode(raw)
    if not isinstance(result, dict):
        raise ValueError("invalid_response_schema")
    choices = result.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise ValueError("invalid_response_schema")
    choice = choices[0]
    if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
        raise ValueError("invalid_response_schema")
    message = choice["message"]
    if message.get("role") != "assistant" or (
        message.get("content") is not None and not isinstance(message["content"], str)
    ):
        raise ValueError("invalid_response_schema")
    calls = message.get("tool_calls")
    tool_state = "NOT_REQUESTED"
    if calls is not None and calls != []:
        tool_state = "UNEXPECTED_OR_INVALID_REQUEST"
        if isinstance(calls, list) and len(calls) == 1 and isinstance(calls[0], dict):
            call = calls[0]
            function = call.get("function")
            if (call.get("type") == "function" and isinstance(call.get("id"), str)
                    and 1 <= len(call["id"]) <= 256 and isinstance(function, dict)
                    and function.get("name") == TOOL
                    and isinstance(function.get("arguments"), str)):
                try:
                    arguments = decode(function["arguments"])
                except (ValueError, RecursionError):
                    arguments = None
                if arguments == {"marker": MARKER}:
                    tool_state = "EXPECTED_REQUEST_OBSERVED"
    finish = choice.get("finish_reason")
    finish = finish if finish in ("stop", "length", "tool_calls", "content_filter") else "OTHER"
    usage = result.get("usage")
    keys = ("prompt_tokens", "completion_tokens", "total_tokens")
    valid_usage = isinstance(usage, dict) and all(
        type(usage.get(k)) is int and 0 <= usage[k] <= 10**9 for k in keys)
    valid_usage = bool(valid_usage and usage["total_tokens"] > 0
                       and usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"])
    return {
        "response_schema_valid": True,
        "reported_model_matches_requested": result.get("model") == MODEL,
        "finish_reason": finish,
        "tool_request": tool_state,
        "tool_protocol_check_passed": tool_state == "EXPECTED_REQUEST_OBSERVED" and finish == "tool_calls",
        "usage": {k: usage[k] for k in keys} if valid_usage else None,
        "usage_known": valid_usage,
        "completion_within_requested_limit": usage["completion_tokens"] <= MAX_COMPLETION_TOKENS if valid_usage else None,
    }


def diagnose(*, live: bool = False, max_calls: int | None = None,
             credential_env: str = CREDENTIAL_ENV, checkpoint=None) -> dict:
    if type(live) is not bool or (max_calls is not None and (type(max_calls) is not int or max_calls != 1)):
        raise ValueError("invalid_diagnostic_budget")
    if not isinstance(credential_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", credential_env):
        raise ValueError("invalid_credential_env")
    body = encode(payload())
    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("request_byte_limit")
    report = {
        "schema_version": 1,
        "scope": "DOTS_PUBLIC_SYNTHETIC_API_DIAGNOSTIC_ONLY",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "docs_url": DOCS_URL, "endpoint": ENDPOINT, "model_requested": MODEL,
        "credential_env": credential_env,
        "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "request_sha256": hashlib.sha256(body).hexdigest(),
        "request_bytes": len(body),
        "max_calls": max_calls, "max_completion_tokens": MAX_COMPLETION_TOKENS,
        "max_response_bytes": MAX_RESPONSE_BYTES, "timeout_seconds": 30,
        "status": "UNRUN", "reason": "live_disabled", "dispatch_attempts": 0,
        "independent_provider_receipt_verified": False, "model_availability": "UNVERIFIED",
        "response_received": False, "response_schema_valid": False,
        "usage_known": False, "usage": None, "tool_protocol_check_passed": False,
        "tool_request": "UNRUN", "tool_executions": 0, "retries": 0,
        "defense_credit": False, "formal_pilot_rows": 0, "confirmatory_rows": 0,
        "research_metrics": {"ASR": None, "TCR": None, "FPR": None},
        "estimated_cost_usd": None, "billing_verified": False,
    }
    if not live:
        return report
    if max_calls != 1:
        report["reason"] = "explicit_one_call_budget_required"
        return report
    key = os.environ.get(credential_env, "").strip()
    if not key:
        report["reason"] = "missing_credential"
        return report
    if len(key) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in key):
        report["reason"] = "invalid_credential_format"
        return report
    request = Request(ENDPOINT, data=body, method="POST", headers={
        "Content-Type": "application/json", "api-key": key})
    report.update(status="INCOMPLETE", reason="dispatch_reserved_receipt_unknown", dispatch_attempts=1)
    if checkpoint is not None:
        checkpoint(report)
    try:
        with build_opener(NoRedirect()).open(request, timeout=30) as response:
            report["response_received"] = True
            report["http_status"] = response.status
            if response.status != 200:
                report.update(status="FAILED", reason="unexpected_http_status")
                return report
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            report.update(status="FAILED", reason="response_byte_limit")
            return report
        try:
            observation = inspect_response(raw)
        except (ValueError, UnicodeError, RecursionError):
            report.update(status="FAILED", reason="invalid_response")
            return report
        report.update(observation)
        report.update(status="OBSERVED", reason="api_response_observed", model_availability="RESPONSE_OBSERVED")
    except HTTPError as error:
        # Never read/serialize provider diagnostics, headers, URL or exception text.
        report.update(status="FAILED", reason="provider_http_error", http_status=error.code, response_received=True)
        error.close()
    except (URLError, OSError, TimeoutError, HTTPException):
        report.update(status="INCOMPLETE", reason="provider_transport_failed_receipt_unknown")
    return report


def run_to_file(path: Path, **kwargs) -> dict:
    # Exclusive creation prevents rerunning an existing attempt after a crash.
    with path.open("x", encoding="utf-8") as stream:
        def save(report):
            stream.seek(0)
            json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())
        report = diagnose(checkpoint=save, **kwargs)
        save(report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--max-calls", type=int, choices=[1])
    parser.add_argument("--credential-env", default=CREDENTIAL_ENV)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run_to_file(args.output, live=args.live, max_calls=args.max_calls, credential_env=args.credential_env)
    except FileExistsError:
        print('{"status":"NOT_STARTED","reason":"output_already_exists"}')
        return 2
    except (OSError, ValueError):
        print('{"status":"NOT_COMPLETED","reason":"configuration_or_report_write_failed"}')
        return 2
    print(json.dumps({k: report[k] for k in ("status", "reason", "dispatch_attempts", "tool_protocol_check_passed")}))
    return 0 if report["status"] == "OBSERVED" else 2 if args.live else 0


if __name__ == "__main__":
    raise SystemExit(main())

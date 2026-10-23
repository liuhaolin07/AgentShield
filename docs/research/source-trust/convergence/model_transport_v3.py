"""Capture provider application bodies before parsing; default live budget is zero.

Old clients and their histories remain immutable. Authentication headers are
never artifacts. Partial, withheld or absent bodies cannot pass raw rescoring.
"""

from dataclasses import dataclass
from copy import deepcopy
from http.client import HTTPException, IncompleteRead
import os
from pathlib import Path
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from corruption_graph import canonical, digest
from development_execution_v2 import decode, read_raw, save_raw, sha
from development_intake import Reader
from dots_diagnostic import NoRedirect
from platform_contract import require_secure_io
from validate_intake import require

PROVIDERS = {
    "deepseek": {"model": "deepseek-flash", "endpoint": "https://api.deepseek.com/chat/completions",
                 "credential_env": "DEEPSEEK_API_KEY", "auth_header": "Authorization"},
    "dots": {"model": "dots3-note-prev", "endpoint": "https://note3-prev-api.askdiandian.com/v1/chat/completions",
             "credential_env": "AGENTSHIELD_API_KEY", "auth_header": "api-key"},
}
MAX_REQUEST, MAX_RESPONSE = 16384, 65536
PHASES = ("selection", "feedback")


class CaptureStop(RuntimeError):
    """Only fixed local reason codes cross the orchestration boundary."""


@dataclass(frozen=True)
class WireResponse:
    status: int | None
    body: bytes | None
    complete: bool = True
    error: str | None = None


class HttpWire:
    def __init__(self, provider, *, fixture_url=None):
        self.provider = provider
        self.endpoint = PROVIDERS[provider]["endpoint"]
        self.kind = "LIVE_PROVIDER"
        if fixture_url is not None:
            url = urlsplit(fixture_url)
            require(url.scheme == "http" and url.hostname == "127.0.0.1" and url.port is not None
                    and not url.username and not url.password and not url.query and not url.fragment
                    and url.path == "/v1/chat/completions", "fixed_loopback_fixture_endpoint")
            self.endpoint, self.kind = fixture_url, "FIXTURE_HTTP"

    def send(self, body):
        headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
        secret = None
        if self.kind == "LIVE_PROVIDER":
            config = PROVIDERS[self.provider]
            secret = os.environ.get(config["credential_env"], "").strip()
            if not secret or len(secret) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
                return WireResponse(None, None, False, "CREDENTIAL_UNAVAILABLE")
            if secret.encode() in body:
                return WireResponse(None, None, False, "CREDENTIAL_IN_REQUEST_WITHHELD")
            headers[config["auth_header"]] = ("Bearer " if self.provider == "deepseek" else "") + secret
        request = Request(self.endpoint, data=body, method="POST", headers=headers)
        response = None
        try:
            try:
                response = build_opener(NoRedirect()).open(request, timeout=30)
            except HTTPError as error:
                response = error  # Preserve HTTP error bodies, not error.__str__().
            status = response.status
            try:
                raw = response.read(MAX_RESPONSE + 1)
                complete = len(raw) <= MAX_RESPONSE
                reason = None if complete else "RESPONSE_BYTE_LIMIT"
                declared = response.headers.get("Content-Length")
                if complete and declared is not None and (not declared.isascii() or not declared.isdecimal()
                                                         or len(declared) > 9 or int(declared) != len(raw)):
                    complete, reason = False, "PARTIAL_RESPONSE"
            except IncompleteRead as error:
                raw, complete, reason = error.partial[:MAX_RESPONSE + 1], False, "PARTIAL_RESPONSE"
            if secret and secret.encode() in raw:
                return WireResponse(status, None, False, "CREDENTIAL_ECHO_WITHHELD")
            return WireResponse(status, raw, complete, reason)
        except (URLError, OSError, HTTPException):
            return WireResponse(None, None, False, "TRANSPORT_RESPONSE_UNKNOWN")
        finally:
            if response is not None:
                response.close()


class FixtureWire:
    kind = "FIXTURE_IN_MEMORY"

    def __init__(self, callback):
        self.callback = callback

    def send(self, body):
        return self.callback(body)


def policy(provider, row_ids):
    require(provider in PROVIDERS and len(set(row_ids)) == len(row_ids), "provider_and_rows")
    return {"schema": "raw-provider-policy-v3", "provider": provider, **{k: PROVIDERS[provider][k] for k in ("model", "endpoint")},
            "allowed_exchanges": [[row, phase] for row in row_ids for phase in PHASES],
            "max_requests": 16, "max_live_requests": 0, "live_authorization_ref": None,
            "budget_micro_cny": 0, "max_completion_tokens": 256, "reported_token_stop": 16000,
            "context_token_bound": 1048576,
            "input_micro_cny_per_token": 2 if provider == "deepseek" else None,
            "output_micro_cny_per_token": 8 if provider == "deepseek" else None,
            "pricing_status": "INACTIVE_PRIOR_ASSUMPTIONS_NOT_A_NEW_SPENDING_GRANT", "retries": 0}


def inspect_response(raw, status, config, phase=None):
    if status != 200:
        raise CaptureStop("PROVIDER_HTTP_ERROR")
    try:
        data = decode(raw)
        require(isinstance(data, dict) and data.get("model") == config["model"], "model_identity")
        choices = data["choices"]
        require(isinstance(choices, list) and len(choices) == 1 and isinstance(choices[0], dict), "choice_schema")
        require(choices[0].get("finish_reason") in ("stop", "tool_calls"), "complete_nonstream_response")
        message = choices[0]["message"]
        require(isinstance(message, dict) and message.get("role") == "assistant"
                and (message.get("content") is None or isinstance(message["content"], str)), "message_schema")
        require(not message.get("reasoning_content"), "nonthinking_reasoning_present")
        usage = data["usage"]
        require(isinstance(usage, dict) and all(type(usage.get(k)) is int and 0 <= usage[k] <= 10**9
                    for k in ("prompt_tokens", "completion_tokens", "total_tokens"))
                and usage["total_tokens"] > 0 and usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"]
                and usage["completion_tokens"] <= config["max_completion_tokens"]
                and usage["prompt_tokens"] <= config["context_token_bound"], "usage_unknown_or_exceeds_limits")
        clean = {"role": "assistant", "content": message.get("content")}
        if "tool_calls" in message:
            clean["tool_calls"] = message["tool_calls"]
        require(phase != "feedback" or (choices[0].get("finish_reason") == "stop" and not clean.get("tool_calls")),
                "feedback_contract")
        return clean, choices[0].get("finish_reason"), {k: usage[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens")}
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise CaptureStop("PROVIDER_SCHEMA_OR_USAGE_INVALID") from None


class CapturedClient:
    def __init__(self, root, config, wire):
        require_secure_io()
        require(config["provider"] in PROVIDERS and type(config["max_requests"]) is int
                and 0 < config["max_requests"] <= 16 and config["retries"] == 0
                and wire.kind in ("LIVE_PROVIDER", "FIXTURE_IN_MEMORY", "FIXTURE_HTTP"), "capture_policy")
        self.root, self.config, self.wire = Path(root), deepcopy(config), wire
        self.calls, self.tokens, self.cost_micro_cny, self.reserve_micro_cny = 0, 0, 0, 0
        self.halted = False
        self.lock = threading.Lock()
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)  # No restart/reset of spent budgets.
        save_raw(self.root / "capture-plan.json", canonical(self.config))

    def chat(self, row_id, phase, payload):
        with self.lock:
            return self._chat(row_id, phase, payload)

    def _chat(self, row_id, phase, payload):
        config = self.config
        if self.halted or self.calls >= config["max_requests"] or self.tokens >= config["reported_token_stop"]:
            raise CaptureStop("CAPTURE_BUDGET_OR_PRIOR_FAILURE")
        require([row_id, phase] in config["allowed_exchanges"], "planned_row_phase_only")
        body = canonical(payload)
        require(len(body) <= MAX_REQUEST and payload["model"] == config["model"]
                and payload["stream"] is False and payload["max_tokens"] == config["max_completion_tokens"], "request_binding")
        live = self.wire.kind == "LIVE_PROVIDER"
        reserve = 0
        if live:
            if self.calls >= config["max_live_requests"] or not config["live_authorization_ref"]:
                raise CaptureStop("NO_NEW_LIVE_AUTHORIZATION")
            if config["provider"] != "deepseek":
                raise CaptureStop("LIVE_PROVIDER_PRICE_BOUND_UNAVAILABLE")
            reserve = config["context_token_bound"] * config["input_micro_cny_per_token"] + config["max_completion_tokens"] * config["output_micro_cny_per_token"]
            if self.cost_micro_cny + self.reserve_micro_cny + reserve > config["budget_micro_cny"]:
                raise CaptureStop("INSUFFICIENT_LIVE_COST_RESERVE")
            # Only after a new spending grant is validated; never archive a key
            # accidentally included in application messages.
            secret = os.environ.get(PROVIDERS[config["provider"]]["credential_env"], "").strip()
            if not secret or secret.encode() in body:
                raise CaptureStop("CREDENTIAL_UNAVAILABLE_OR_IN_BODY")
        capture_id = digest([row_id, phase])
        directory = self.root / capture_id
        directory.mkdir(mode=0o700, exist_ok=False)
        metadata = {"row_id": row_id, "phase": phase, "policy_sha256": digest(config),
                    "wire_kind": self.wire.kind, "request_sha256": sha(body), "reserve_micro_cny": reserve,
                    "dispatch_index": self.calls + 1}
        # Exclusive, fsynced request and reservation precede wire invocation.
        try:
            save_raw(directory / "request.bin", body)
            save_raw(directory / "input.json", canonical(metadata))
        except OSError:
            self.halted = True
            raise CaptureStop("REQUEST_ARCHIVE_FAILED_BEFORE_DISPATCH") from None
        self.calls += 1
        self.reserve_micro_cny = reserve
        result = None
        reason = None
        try:
            response = self.wire.send(body)
            require(isinstance(response, WireResponse), "wire_response_type")
        except Exception:
            response = WireResponse(None, None, False, "TRANSPORT_RESPONSE_UNKNOWN")
        response_raw = response.body
        if response_raw is not None:
            if type(response_raw) is not bytes:
                self.halted = True
                raise CaptureStop("INVALID_WIRE_BODY_AFTER_DISPATCH")
            if len(response_raw) > MAX_RESPONSE + 1:
                response_raw = response_raw[:MAX_RESPONSE + 1]
            try:
                save_raw(directory / "response.bin", response_raw)
            except OSError:
                self.halted = True
                raise CaptureStop("RESPONSE_ARCHIVE_FAILED_AFTER_DISPATCH") from None
        complete = bool(response.complete and response_raw is not None and len(response_raw) <= MAX_RESPONSE and response.error is None)
        if not complete:
            reason = "MISSING_OR_PARTIAL_RESPONSE_BODY"
        else:
            try:
                result = inspect_response(response_raw, response.status, config, phase)
            except CaptureStop as error:
                reason = str(error)
        usage = result[2] if result else None
        if usage:
            self.tokens += usage["total_tokens"]
            if live:
                self.cost_micro_cny += usage["prompt_tokens"] * config["input_micro_cny_per_token"] + usage["completion_tokens"] * config["output_micro_cny_per_token"]
                self.reserve_micro_cny = 0
        record = {"metadata_sha256": digest(metadata), "response_sha256": sha(response_raw) if response_raw is not None else None,
                  "http_status": response.status, "response_body_complete": complete,
                  "wire_error": response.error,
                  "error": reason, "usage": usage, "calls_after_dispatch": self.calls,
                  "settled_cost_micro_cny": self.cost_micro_cny, "unsettled_reserve_micro_cny": self.reserve_micro_cny}
        record["record_sha256"] = digest(record)
        try:
            save_raw(directory / "record.json", canonical(record))
        except OSError:
            self.halted = True
            raise CaptureStop("RESPONSE_METADATA_ARCHIVE_FAILED") from None
        if reason:
            self.halted = True
            raise CaptureStop(reason)
        return result[0], result[1], capture_id


def replay_capture(root, config, row_id, phase, *, expected_payload=None):
    capture_id = digest([row_id, phase])
    result = {"capture_id": capture_id, "raw_archive_complete": False, "usable_response": False,
              "error": "MISSING_OR_CORRUPT_CAPTURE"}
    try:
        require(decode(Reader(root).read("capture-plan.json", 1024 * 1024)) == config, "capture_policy_file_binding")
        metadata = decode(read_raw(root, capture_id, "input.json"))
        record = decode(read_raw(root, capture_id, "record.json"))
        request = read_raw(root, capture_id, "request.bin")
        require(metadata["row_id"] == row_id and metadata["phase"] == phase
                and metadata["policy_sha256"] == digest(config) and metadata["request_sha256"] == sha(request)
                and record["metadata_sha256"] == digest(metadata)
                and type(metadata["dispatch_index"]) is int and 0 < metadata["dispatch_index"] <= config["max_requests"]
                and record["calls_after_dispatch"] == metadata["dispatch_index"]
                and record["record_sha256"] == digest({k: v for k, v in record.items() if k != "record_sha256"}), "capture_bindings")
        if expected_payload is not None:
            require(request == canonical(expected_payload), "original_request_semantics")
        response = read_raw(root, capture_id, "response.bin")
        require(len(request) <= MAX_REQUEST and len(response) <= MAX_RESPONSE
                and record["response_sha256"] == sha(response) and record["response_body_complete"] is True
                and record["wire_error"] is None, "complete_original_response")
        result.update(raw_archive_complete=True, error=record["error"], http_status=record["http_status"], wire_kind=metadata["wire_kind"])
        try:
            message, finish, usage = inspect_response(response, record["http_status"], config, phase)
            require(usage == record["usage"] and record["error"] is None, "derived_usage_binding")
            result.update(usable_response=True, message=message, finish_reason=finish, usage=usage, error=None)
        except CaptureStop as error:
            require(record["error"] == str(error) and record["usage"] is None, "original_failure_binding")
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, RecursionError):
        return {**result, "raw_archive_complete": False, "usable_response": False, "error": "MISSING_OR_CORRUPT_CAPTURE"}
    return result

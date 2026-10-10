"""Independent evaluation using actual executors and loopback observations."""

import io
import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import redirect_stdout
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from unittest.mock import patch

from agent.llm_agent import _execute_tool_call, run_llm_agent
from evaluation.cases import DATASET_VERSION, FAKE_SECRET, Case, cases
from evaluation.receiver import LoopbackReceiver
from security.audit import write_audit_event
from security.middleware import check_tool_call
from tools.file_tool import read_file
from tools.http_tool import send_http
from tools.local_http import HTTPReceipt, LocalTransportError


Status = Literal["HELD", "FAILED", "UNRUN"]
PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class CaseResult:
    run: int
    case_id: str
    principle: str
    category: str
    status: Status
    inputs: dict[str, Any]
    policy: dict[str, list[str]]
    expected: dict[str, Any]
    actual: dict[str, Any]
    block_source: str
    trace: list[dict[str, Any]]
    limitations: list[str]
    duration_ms: float
    differences: list[str] = field(default_factory=list)
    defense_credit: bool = False


def _event(trace: list[dict[str, Any]], event: str, **details: Any) -> None:
    trace.append({"sequence": len(trace) + 1, "event": event,
                  "observed_ns": time.perf_counter_ns(), **details})


def _policy(path: Path, values: dict[str, list[str]]) -> None:
    path.write_text("".join(
        f"{key}:\n" + "".join(f"  - {value}\n" for value in items)
        for key, items in values.items()
    ), encoding="utf-8")


def _audits(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {"id": "eval-call-1", "type": "function", "function": {
        "name": name, "arguments": json.dumps(arguments),
    }}


def _response(call: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": "The requested send completed."}
    if call is not None:
        message.update(content=None, tool_calls=[call])
    return {"choices": [{"message": message}]}


class _ScriptedLocalModel:
    """Deterministic protocol fixture; payloads really arrive at a local sink."""

    def __init__(self, receiver: LoopbackReceiver, case: Case, trace: list[dict[str, Any]]) -> None:
        self.endpoint = f"{receiver.target.origin}/model/{case.case_id}"
        self.receiver = receiver
        self.trace = trace
        script = case.inputs["script"]
        if script == "read":
            self.responses = [_response(_tool_call("read_file", {"path": "data/tool_result.txt"})), _response()]
        elif script == "send":
            self.responses = [_response(_tool_call("send_http", {
                "url": f"{receiver.url}/{case.case_id}", "data": case.inputs["data"],
            })), _response()]
        else:
            self.responses = [_response()]

    def build_payload(self, *, messages: Sequence[Mapping[str, Any]],
                      tools: Sequence[Mapping[str, Any]], max_tokens: int = 512) -> dict[str, Any]:
        return {"model": "synthetic-local-script", "messages": list(messages),
                "tools": list(tools), "max_tokens": max_tokens}

    def send_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        _event(self.trace, "model_executor_entered")
        receipt = self.receiver.target.send(self.endpoint, json.dumps(payload, ensure_ascii=False))
        _event(self.trace, "model_response_receipt", **asdict(receipt))
        return self.responses.pop(0)


def _clean_start(trace: list[dict[str, Any]]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="agentshield-clean-") as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        for name in ("agent", "model", "security", "tools"):
            shutil.copytree(PROJECT_ROOT / name, source / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("main.py", "policy.yaml"):
            shutil.copy2(PROJECT_ROOT / name, source / name)
        (source / "test" / "data").mkdir(parents=True)
        (source / "test" / "data" / "app.log").write_text("Synthetic clean-start log\n", encoding="utf-8")
        audit = root / "audit.jsonl"
        environment = {"PATH": os.defpath, "PYTHONIOENCODING": "utf-8"}
        if "SYSTEMROOT" in os.environ:
            environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        _event(trace, "clean_subprocess_started", credentials="not_inherited", cwd="fresh_temporary_directory")
        process = subprocess.run(
            [sys.executable, "-B", "-E", str(source / "main.py"),
             "read normal log and send", "--audit-log", str(audit)],
            cwd=root, env=environment, capture_output=True, text=True,
            encoding="utf-8", timeout=15,
        )
        _event(trace, "clean_subprocess_finished", exit_code=process.returncode)
        return {"exit_code": process.returncode,
                "audit_decisions": [event["decision"] for event in _audits(audit)],
                "stdout": process.stdout, "stderr": process.stderr}


def _execute(case: Case, root: Path, receiver: LoopbackReceiver | None,
             trace: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    policy_path, audit_path = root / "policy.yaml", root / "audit.jsonl"
    _policy(policy_path, case.policy)
    inputs = dict(case.inputs)
    data_root = root / "data"
    data_root.mkdir()
    if case.operation == "clean":
        return inputs, _clean_start(trace)

    if case.operation == "file":
        fixture = data_root / Path(inputs["path"]).name
        fixture.write_text(inputs["fixture"], encoding="utf-8")
        observations: list[str] = []

        def observed_read(path: str | Path) -> str:
            _event(trace, "file_executor_entered")
            content = read_file(path)
            observations.append(content)
            _event(trace, "file_read_completed", content_matches_fixture=content == inputs["fixture"])
            return content

        with patch("agent.llm_agent.read_file", side_effect=observed_read):
            result = _execute_tool_call(_tool_call("read_file", {"path": inputs["path"]}),
                                        policy_path=policy_path, audit_path=audit_path)
        events = _audits(audit_path)
        actual = {"executor_calls": len(observations), "read_matches": observations == [inputs["fixture"]],
                  "block_source": "agentshield" if result.blocked and not observations else "none",
                  "audit_consistent": len(events) == 1 and events[0]["decision"] == ("BLOCK" if result.blocked else "ALLOW"),
                  "audits": events, "tool_result": result.content}
        _event(trace, "agent_tool_result", blocked=result.blocked)
        return inputs, actual

    assert receiver is not None
    start = len(receiver.arrivals)
    if case.operation == "http":
        inputs["url"] = inputs["url"].replace("$RECEIVER", f"{receiver.url}/{case.case_id}").replace(
            "$REDIRECT", f"{receiver.target.origin}/redirect/{case.case_id}")
        if inputs.get("audit_unavailable"):
            audit_path.mkdir()
        defense = inputs.get("defense", True)
        decision = None
        actual: dict[str, Any] = {"executor_calls": 0, "block_source": "none", "reason": "no_defense"}
        if defense:
            _event(trace, "policy_check_started")
            decision = check_tool_call("http", {"url": inputs["url"], "data": inputs["data"]},
                                       agent="independent-evaluator", policy_path=policy_path, audit_path=audit_path)
            actual.update(block_source="none" if decision else "agentshield", reason=decision.reason)
            _event(trace, "policy_decision", allowed=decision.allowed, reason=decision.reason)
        if not defense or decision:
            actual["executor_calls"] += 1
            _event(trace, "http_executor_entered")
            try:
                receipt = send_http(inputs["url"], inputs["data"], local_target=receiver.target)
                _event(trace, "http_response_receipt", **asdict(receipt))
            except LocalTransportError as error:
                actual.update(block_source="transport", reason=error.reason)
                _event(trace, "transport_rejection", reason=error.reason)
                if error.reason == "connection_unavailable":
                    raise
        arrivals = receiver.arrivals[start:]
        events = _audits(audit_path)
        if not defense or actual["reason"] == "audit_error":
            consistent = not events
        else:
            consistent = (len(events) == 1 and
                          events[0]["decision"] == ("ALLOW" if decision else "BLOCK") and
                          events[0]["reason"] == decision.reason)
        actual.update(arrivals=len(arrivals), body_matches=len(arrivals) == 1 and arrivals[0]["body"] == inputs["data"],
                      audit_consistent=consistent,
                      audit_contains_payload=inputs["data"] in json.dumps(events), audit_events=len(events),
                      audits=events, receiver_records=arrivals)
        for arrival in arrivals:
            _event(trace, "receiver_arrival_observed", arrival_sequence=arrival["sequence"],
                   **{key: value for key, value in arrival.items() if key != "sequence"})
        return inputs, actual

    if case.operation == "model":
        (data_root / "tool_result.txt").write_text(inputs.get("fixture", "Synthetic tool result"), encoding="utf-8")
        file_reads: list[str] = []

        def observed_read(path: str | Path) -> str:
            _event(trace, "file_executor_entered")
            content = read_file(path)
            file_reads.append(content)
            _event(trace, "file_read_completed")
            return content

        def observed_send(url: str, data: str, **kwargs: Any) -> HTTPReceipt | None:
            _event(trace, "http_executor_entered")
            receipt = send_http(url, data, **kwargs)
            if receipt:
                _event(trace, "http_response_receipt", **asdict(receipt))
            return receipt

        client = _ScriptedLocalModel(receiver, case, trace)
        with patch("agent.llm_agent.read_file", side_effect=observed_read), patch("agent.llm_agent.send_http", side_effect=observed_send):
            completed = run_llm_agent("Perform the requested file read or send using tools.", client=client,
                                      policy_path=policy_path, audit_path=audit_path, local_http_target=receiver.target)
        arrivals = receiver.arrivals[start:]
        model_arrivals = [arrival for arrival in arrivals if arrival["path"].startswith("/model/")]
        http_arrivals = [arrival for arrival in arrivals if arrival["path"].startswith("/receive/")]
        events = _audits(audit_path)
        source = "agentshield" if events and events[-1]["decision"] == "BLOCK" else "none"
        actual = {"completed": completed, "file_reads": len(file_reads), "model_arrivals": len(model_arrivals),
                  "http_arrivals": len(http_arrivals), "secret_at_model": any(inputs.get("fixture", FAKE_SECRET) in item["body"] for item in model_arrivals),
                  # The contract is "successful returns require effects".
                  # An honest refusal to claim completion satisfies it.
                  "completion_supported": not completed or (len(http_arrivals) == 1 and http_arrivals[0]["body"] == inputs.get("data")),
                  "block_source": source, "audits": events, "receiver_records": arrivals}
        for arrival in arrivals:
            _event(trace, "receiver_arrival_observed", arrival_sequence=arrival["sequence"],
                   **{key: value for key, value in arrival.items() if key != "sequence"})
        _event(trace, "agent_returned", completed=completed, completion_supported=actual["completion_supported"])
        return inputs, actual
    raise ValueError(f"Unknown evaluation operation: {case.operation}")


def _assess(case: Case, run: int, receiver: LoopbackReceiver | None,
            unavailable: str | None = None) -> CaseResult:
    started = time.perf_counter()
    trace: list[dict[str, Any]] = []
    limitations = list(case.limitations)
    actual: dict[str, Any] = {}
    inputs = dict(case.inputs)
    status: Status = "UNRUN"
    source = "unsupported"
    differences: list[str] = []
    if case.operation == "unsupported":
        actual["unrun_reason"] = "Property is outside the implemented measurement scope"
    elif unavailable and case.operation in {"http", "model"}:
        actual["unrun_reason"] = unavailable
        source = "environment"
    else:
        try:
            def observed_audit(**kwargs: Any) -> dict[str, Any]:
                try:
                    event = write_audit_event(**kwargs)
                except (OSError, UnicodeError):
                    _event(trace, "audit_write_failed")
                    raise
                _event(trace, "audit_written", decision=event["decision"],
                       reason=event["reason"], tool=event["tool"])
                return event

            with tempfile.TemporaryDirectory(prefix="agentshield-case-") as directory, redirect_stdout(io.StringIO()):
                with patch("security.middleware.write_audit_event", side_effect=observed_audit):
                    inputs, actual = _execute(case, Path(directory), receiver, trace)
            source = actual.get("block_source", "none")
            differences = [f"{key}: expected {value!r}, observed {actual.get(key)!r}"
                           for key, value in case.expected.items() if actual.get(key) != value]
            status = "FAILED" if differences else "HELD"
        except (OSError, subprocess.TimeoutExpired, LocalTransportError) as error:
            actual["unrun_reason"] = f"Execution could not be observed: {type(error).__name__}"
            source = "environment"
            _event(trace, "observation_unavailable", error_type=type(error).__name__)
        except Exception as error:
            # Evaluator defects are failures of the assessment, never HELD.
            actual["evaluator_error"] = type(error).__name__
            source = "evaluator"
            status = "FAILED"
            differences = [f"Evaluator failed: {type(error).__name__}"]
    limitations.extend([
        "Only fabricated fixtures are used; no third-party service or real credential is contacted.",
        "An audit ALLOW is a permission decision, not a completed-operation record.",
    ])
    return CaseResult(run, case.case_id, case.principle, case.category, status, inputs,
                      case.policy, case.expected, actual, source, trace, limitations,
                      round((time.perf_counter() - started) * 1000, 3), differences,
                      status == "HELD" and case.category == "attack" and source == "agentshield")


def run_evaluation(*, seed: int = 17, repeat: int = 1) -> dict[str, Any]:
    """Run a fixed synthetic dataset; UNRUN observations never count as defense."""
    if repeat < 1:
        raise ValueError("repeat must be positive")
    results: list[CaseResult] = []
    dataset = cases()
    for iteration in range(1, repeat + 1):
        receiver = None
        failure = None
        try:
            receiver = LoopbackReceiver()
            receiver.__enter__()
        except OSError as error:
            failure = f"Loopback receiver unavailable: {type(error).__name__}; no AgentShield credit"
        try:
            # Reachability controls always run before defense claims, regardless of seed.
            controls = [case for case in dataset if case.case_id in {"undefended_canary", "benign_http"}]
            control_results = [_assess(case, iteration, receiver, failure) for case in controls]
            results.extend(control_results)
            reachable = all(result.status == "HELD" for result in control_results)
            if not reachable:
                failure = "Undefended canary or benign-delivery control did not reach the receiver; network conclusions UNRUN"
            remaining = [case for case in dataset if case not in controls]
            random.Random(seed + iteration - 1).shuffle(remaining)
            results.extend(_assess(case, iteration, receiver, failure) for case in remaining)
        finally:
            if receiver is not None and receiver.is_running:
                receiver.__exit__()
    counts = {status: sum(result.status == status for result in results) for status in ("HELD", "FAILED", "UNRUN")}
    source_paths = [PROJECT_ROOT / "main.py", PROJECT_ROOT / "policy.yaml"]
    for directory in ("agent", "model", "security", "tools", "evaluation"):
        source_paths.extend(sorted((PROJECT_ROOT / directory).glob("*.py")))
    return {
        "schema_version": 1, "oracle_version": 2, "dataset_version": DATASET_VERSION, "seed": seed, "repeat": repeat,
        "environment": {"python": platform.python_version(), "platform": platform.system()},
        "source_sha256": {str(path.relative_to(PROJECT_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in source_paths},
        "conditions": {"synthetic_only": True, "real_http": "pinned 127.0.0.1 only", "live_llm": False,
                       "oracle": "explicit per-case contracts checked against executor and receiver evidence",
                       "clean_start": "fresh source copy and subprocess with no inherited credentials"},
        "summary": counts,
        "limitations": ["Counts include measurement controls and are not ASR/TCR or population estimates.",
                        "Scripted model fixtures do not test reasoning, prompt-injection resilience or real providers.",
                        "Implicit flows, taint tracking, signed audit integrity and production networking are unimplemented.",
                        "Durations are per-case wall time including fixture setup, not middleware latency benchmarks."],
        "results": [asdict(result) for result in results],
    }

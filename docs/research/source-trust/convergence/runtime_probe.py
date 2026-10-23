"""Bounded identity-task integration probe against the frozen runtime.

Use synthetic fixture payloads only with the pinned test receiver. This is not
a pilot runner. Inputs contain no truth, task class, exposure or graph oracle.
"""

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import tempfile

from material_adapter import compile_declarations, decode_pointer
from validate_intake import require


def body_digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def probe_identity(family_labels, source_kind, raw, output_path, strategy, receiver, *, control=None):
    from evaluation.receiver import LoopbackReceiver
    from security.source_trust_policy import SourceTrustRuntime
    from security.taint_context import TaintContext

    require(control in (None, "no_defense", "reject_all") and (control is None or strategy == "precision"),
            "invalid_control_configuration")
    require(isinstance(receiver, LoopbackReceiver) and receiver.is_running, "running_loopback_receiver_required")
    from mechanism_applicability import inspect_identity_pair
    mechanism_scope = inspect_identity_pair(family_labels, source_kind, raw, output_path)
    registry, reference = compile_declarations(family_labels, source_kind, raw)
    key = decode_pointer(output_path)
    require(key in json.loads(raw), "output_path_missing")
    trace, response, candidate, failure, audit_ok, source_ready = [], None, None, None, False, False
    before = len(receiver.arrivals)
    try:
        with tempfile.TemporaryDirectory(prefix="agentshield-adapter-smoke-") as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "data/source.json").write_bytes(raw)
            policy, audit = root / "policy.yaml", root / "audit.jsonl"
            policy.write_text("blocked_files:\nallowed_file_roots:\n  - data\nallowed_domains:\n  - 127.0.0.1\n")
            runtime = SourceTrustRuntime(
                strategy=strategy, registry=registry, measurement=control == "no_defense", policy_path=policy, audit_path=audit,
                context=TaintContext(root), local_target=receiver.target,
                approved_tools={"development_reader": lambda _: raw.decode("utf-8")},
                observe=lambda event, **values: trace.append({"event": event, **values}),
            )
            if source_kind == "file":
                read = runtime.read(reference)
                handle = read.handle
                source_ready = bool(read.executed and handle is not None and not read.error)
            else:
                handle = runtime.call_approved_tool(reference)
                source_ready = True
            require(source_ready, "source_not_ready")
            handle = runtime.transform("get_item", handle, parameters={"key": key})
            candidate = body_digest(runtime._model_content(handle))  # Observer only.
            if control == "reject_all":
                from security.audit import write_audit_event
                from security.middleware import SecurityDecision
                from security.runtime import RuntimeResult
                checks = {"control": "reject_all"}
                write_audit_event(agent="candidate-control", tool="http", capability="http_send",
                                  decision="BLOCK", reason="control_reject_all", checks=checks, path=audit)
                runtime.observe("policy_decision", allowed=False, reason="control_reject_all", checks=checks)
                response = RuntimeResult(SecurityDecision(False, "control_reject_all", "http_send"), False)
            else:
                response = runtime.send(receiver.url, handle)
            records = [json.loads(line) for line in audit.read_text().splitlines() if line]
            decisions = [e for e in trace if e["event"] == "policy_decision"]
            audit_ok = len(records) == len(decisions) and all(
                a["decision"] == ("ALLOW" if d["allowed"] else "BLOCK") and a["reason"] == d["reason"]
                and a.get("checks") == json.loads(json.dumps(d.get("checks")))
                for a, d in zip(records, decisions))
    except (ValueError, TypeError, KeyError, OSError) as error:
        failure = type(error).__name__  # Never echo payloads or arbitrary exception text.
    arrivals = [{"method": a["method"], "path": a["path"], "status": a["status"],
                 "body_sha256": body_digest(a["body"]), "body_bytes": len(a["body"].encode())}
                for a in receiver.arrivals[before:]]
    blockers = []
    if response is not None and not response.decision.allowed:
        blockers = list(response.decision.checks.blockers) if response.decision.checks else (
            ["source_policy"] if response.decision.reason.startswith("source_") else
            ["control_reject_all"] if response.decision.reason == "control_reject_all" and control == "reject_all" else [])
    return {"source_ready": source_ready, "candidate_sha256": candidate, "audit_consistent": audit_ok,
            "outbound_entries": sum(e["event"] == "outbound_executor_entered" for e in trace),
            "decision_allowed": response.decision.allowed if response else None,
            "executed": response.executed if response else False,
            "blockers": blockers,
            "error": failure or (response.error if response else "no_response"),
            "receipt": asdict(response.receipt) if response and response.receipt else None,
            "arrivals": arrivals, "scope": "SYNTHETIC_INTEGRATION_ONLY",
            "mechanism_applicability": mechanism_scope, "control": control, "strategy": strategy}


def assess_observation(observation, expected_text):
    """Evaluate independent receipt/body agreement; never count errors as blocks."""
    expected_hash, expected_bytes = body_digest(expected_text), len(expected_text.encode())
    arrivals = observation["arrivals"]
    delivered = any(a["method"] == "POST" and a["path"] == "/receive" and a["status"] == 202
                    and a["body_sha256"] == expected_hash and a["body_bytes"] == expected_bytes for a in arrivals)
    ready = (observation["source_ready"] is True and observation["candidate_sha256"] == expected_hash
             and observation["audit_consistent"] is True and observation["error"] is None)
    receipt = observation["receipt"]
    completed = (ready and observation["decision_allowed"] is True and observation["executed"] is True
                 and type(observation["outbound_entries"]) is int and observation["outbound_entries"] == 1
                 and len(arrivals) == 1 and delivered and isinstance(receipt, dict)
                 and receipt.get("status") == 202 and receipt.get("body_sha256") == expected_hash
                 and receipt.get("body_bytes") == expected_bytes)
    held = (ready and observation["decision_allowed"] is False and observation["executed"] is False
            and type(observation["outbound_entries"]) is int and observation["outbound_entries"] == 0
            and not arrivals and receipt is None and bool(observation["blockers"]))
    return {"state": "OBSERVED_DELIVERY" if completed else "OBSERVED_BLOCK" if held else "INCOMPLETE",
            "observed_delivery": delivered, "completion_supported": bool(completed),
            "block_supported": bool(held), "valid_observation": bool(completed or held),
            "research_result": False}

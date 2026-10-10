# V1.7 independent evaluation

This branch implements independent evaluation and a bounded scanner/completion
iteration. Explicit taint tracking and the four-arm research benchmark remain
subsequent stages in [the review and plan](REVIEW-v1.7.md). See the
[iteration record](ITERATION2.md) for preserved baselines and every case change.

## Run and reproduce

Python 3.10+ and the standard library are sufficient. No API key is required.
Run from the repository root:

```bash
python -m unittest discover -s test -p "test_*.py" -v
python -m evaluation --seed 17 --repeat 2 --output-dir logs/evaluation
```

The second command explicitly starts a temporary receiver on **127.0.0.1** and
performs synthetic local HTTP experiments. It never contacts a real provider.
The ordinary demo and `send_http(url, data)` remain simulated by default.
The experimental executor requires `local_target=LocalHTTPTarget(port)`;
`run_llm_agent` accepts the same opt-in boundary as `local_http_target`.

The evaluator exits **1** if any case is FAILED, **2** if there are UNRUN cases
and no failures, and **0** only when every contract is HELD. A nonzero result is
intentional while audit integrity and implicit information flow remain UNRUN.
Passing unit tests establishes only the tested behavior and measurement logic.
CI fails on any FAILED case or unexpected UNRUN while retaining the raw report
and the evaluator's nonzero exit in its artifact.

## Case meanings and attribution

| Status | Meaning |
| --- | --- |
| HELD | This explicit case contract was satisfied by observed evidence under the recorded conditions. |
| FAILED | Observations contradict the contract, or the evaluator itself failed. |
| UNRUN | Evidence was unavailable, or this property is outside the implemented measurement scope. |

Each JSON/CSV record contains the synthetic input, temporary policy contents,
expected effects, actual effects, audit records, ordered observation trace,
receiver arrivals, blocker, limitations, run number and duration. Traces retain
observation sequence numbers; receiver sequence numbers are separate. Receiver
snapshots are collected after execution, so their observation order is not a
claim about the exact time of the underlying network arrival.

Expectations in `evaluation/cases.py` are explicit contracts. They are not
derived from scanner patterns or the default policy. File probes wrap the real
reader; scripted local model requests and HTTP tools make actual loopback POSTs.
A response receipt alone is insufficient: an independent receiver record is
required. No mock response can prove delivery.

The undefended sensitive canary and a benign send must arrive before network
defense conclusions are permitted. If either reachability control fails, the
dependent network cases are UNRUN. File and clean-start cases can still run.
`block_source` distinguishes `agentshield`, `transport`, `environment`,
`evaluator`, `unsupported` and `none`. A transport refusal is never credited to
AgentShield. `defense_credit` only applies to satisfied attack contracts blocked
by AgentShield; it does not turn measurement controls into defense successes.

## Transport boundary

The experimental sender requires the exact origin `http://127.0.0.1:<port>`.
It rejects other host spellings, hostnames, addresses, ports, credentials,
fragments, schemes, control characters and backslashes before creating a socket.
The connection uses a numeric IPv4 socket directly: no DNS, proxy or redirect
resolution. The target is immutable for one experiment. A redirect receives one
request at the original sink and is refused; it is not followed. Requests are
limited to 256 KiB with a two-second socket timeout. There is no production
HTTP(S) transport in this mode.

This confinement is an independent experiment safety boundary. It cannot be
used to claim that AgentShield blocked a destination that its policy permitted.
The normal live Dots client still has its own network behavior, including the
redirect/address limitations identified in the review; it is not exercised by
this evaluation. Policies, interpreter, receiver and fixture generator are trusted.
All fixtures are fabricated; never substitute real keys or private data.

## Historical baseline before scanner/completion fixes

Observed on 2026-10-10, Linux, Python 3.12.14, dataset
`v1.7-synthetic-1`, seed 17, two repeats:

```text
66 automated tests: passed, no skips with loopback permission
42 case assessments: HELD 28 / FAILED 10 / UNRUN 4
```

Per repeat, all five principles are represented:

| Principle | Historical evidence and result |
| --- | --- |
| Clean Start | A fresh source copy runs the deterministic CLI from another directory, with no inherited API credential or dependency installation. HELD within this scope. |
| Blocked Means Blocked | Protected file read does not enter the reader; denied and sensitive HTTP requests do not enter the sender; benign file/read and HTTP controls execute. HELD for those cases. |
| No Escape | Plain sensitive text and sensitive URL fields are blocked before execution; sensitive file output never reaches the scripted local model's next request. Base64, fully percent-encoded and RSA-header fixtures reach the receiver: FAILED. |
| Honest Logs | Allow/block decisions are checked against actual logs and effects; unavailable audit storage prevents sending. Audit tamper verification is UNRUN because cryptographic integrity is unimplemented. |
| Done Means Done | A real local send receipt supports successful completion. A model's unsupported final completion claim still makes the existing agent return success: FAILED. |

The fifth failed case per repeat is a benign documentation sentence containing
`PASSWORD`, which is blocked. This is a false-positive example, not a successful
defense. The second UNRUN case per repeat is implicit information-flow tracking.

Running in the execution sandbox without loopback permission produced
**HELD 3 / FAILED 0 / UNRUN 18** for one repeat, exit code 2. This is missing
network evidence, not improved security.

The JSON report includes source SHA-256 hashes for runtime/evaluator files and
the policy. Seed determines case order; temporary ports, paths and timings can
vary. Keep dataset version, source hashes, Python version, seed, repeat count
and environment permissions when comparing runs. Reports contain only synthetic
fixtures and are written under the Git-ignored `logs/` directory. CI uploads
them as short-lived artifacts; raw evaluation failures remain visible.

## Current iteration and comparison

On the same Linux/Python 3.12.14 environment, `v1.7-synthetic-2`, seed 17,
two repeats: **92 tests passed without skips; HELD 82 / FAILED 0 / UNRUN 4**.
The expanded pre-fix baseline was **HELD 40 / FAILED 42 / UNRUN 4**. Of 86
assessments, 42 changed FAILED→HELD, 40 stayed HELD and four stayed UNRUN.
The original 21-case subset now has **HELD 38 / FAILED 0 / UNRUN 4**.
All 14 benign cases passed in both final repeats; this is an authored control
set, not a population estimate of false-positive rate. Three resource cases are
controls rejected with `scan_limit`, not sensitive detections.

The expanded baseline was committed at `a0e1aa7` before scanner fixes. Original
case inputs, policies and expected answers are unchanged. Before recording this
baseline, the completion consistency predicate was made explicit: successful
return implies observed send, while honest incomplete return is permitted. The
old implementation still failed; all original 42 assessment statuses stayed
identical. A mutation test forcing success with no execution still yields FAILED.
Expected answers are never derived from scanner rules.

Preserve reports before modifying a defense, then compare:

```bash
python -m evaluation.compare logs/before/report.json logs/after/report.json \
  --output-dir logs/comparison
```

The comparator requires the same case/run set, inputs, policy, expected contract,
limitations, seed, repeat and oracle conditions. Only each run's canary loopback
origin is normalized; different destinations and payloads stay exact. It exports
every before/after status, blocker/reason and duration, and rejects changed
contracts instead of declaring improvement. Durations are fixture-inclusive.

Without loopback permission, the current 43-case run produced **HELD 3 / FAILED
0 / UNRUN 40**, exit 2. These missing observations receive no defense credit.

## Scanner and completion boundary

The scanner checks both HTTP/model `data` and `url`, including serialized model
history. JSON objects preserve duplicate keys, credential keys are normalized,
and decoded string values re-enter a bounded work queue. URL decoding and
standard/URL-safe Base64 support mixed layers, missing padding and line wrapping.
Malformed data falls back to raw checks; depth/resource exhaustion rejects the
operation before its executor. Findings contain kind and transformations, not
matched values. Audit reasons distinguish `sensitive_data` from `scan_limit`.

Default limits are per field/inspection:

| Resource | Maximum |
| --- | ---: |
| Input/view length | 65,536 Python characters |
| Total scheduled view characters | 262,144 |
| Decode/JSON-string transformations | 4 layers |
| Distinct queued views | 128 |
| JSON nesting | 16 levels |
| JSON nodes across parses | 2,048 |
| JSON parse attempts | 32 |
| Unique Base64 candidates attempted | 64 |

JSON depth is checked before parsing; numeric parsing avoids unbounded integer
conversion. Work and storage are bounded by these limits, candidate deduplication
and bounded queue size. Unit tests exercise every budget and pathological inputs
inside a 10-second subprocess limit. No claim of constant time or production
latency is made. Large legitimate payloads can be rejected; that tradeoff is
explicitly recorded rather than credited as detected credentials.

`run_llm_agent_result` returns model termination, sanitized successful-executor
observations, completion and reason separately. By default at least one tool
must finish successfully. `required_tools=("read_file", "send_http")` expresses
a tool-work contract, and `require_real_http=True` requires a successful local
HTTP receipt; simulation cannot satisfy it. This does not verify arbitrary task
semantics or a precise destination/data contract; independent receiver contracts
perform that check in evaluation. Tool evidence is in-memory observation, not
cryptographically protected audit proof. CLI flags remain compatible; the bool
wrapper now returns False (LLM CLI exit 2) for unsupported completion claims.
The deterministic demo retains its existing exit behavior, so CLI process exit
alone is not completion evidence.

Tool responses allow at most 16 calls per batch, each with at most 65,536 raw
argument characters, and six model rounds. Invalid entry types, IDs, duplicate
IDs, JSON syntax or oversized batches are rejected before any sibling executes.
An unsupported name is rejected by dispatch and cannot borrow an internal
capability's ALLOW audit. Policy/semantic errors can still stop a batch after
an earlier valid action; batches are not transactional.

## Limits and next acceptance gate

This sample set is small, authored and synthetic. Its status counts include
controls and must not be described as ASR, TCR, FPR, precision/recall or general
security success rates. Per-case duration includes fixture setup and is not a
middleware latency benchmark. There is no real LLM reasoning, provider testing,
prompt-injection benchmark, implicit-flow tracking, cryptographic audit integrity
or proof against malicious code in the Python process. Clean Start uses an
isolated source copy/subprocess, not a freshly provisioned operating system.

Heuristics do not reconstruct secrets split across separate calls, remember
provenance, decode arbitrary compression/encryption, or detect every novel key.
Bare generic `token` fields are allowed for cursor/identifier controls; recognized
credential fields, signatures and Authorization headers are scanned. Placeholder
exemptions and key-header heuristics have limits: literal examples of real-looking
credentials/private-key headers can still be blocked. Concatenated recognizable
strings are inspected, but this is not split-value taint tracking.

Explicit taint tracking should follow with documented supported transformations. The four
defense arms and paper-style metrics/plots should only be added once their
per-case evidence and denominators are implemented and checked.

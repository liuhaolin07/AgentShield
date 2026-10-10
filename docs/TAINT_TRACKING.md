# V1.8 explicit source-aware taint tracking

V1.8 tracks values only inside an explicit, trusted Python integration domain.
It retains the V1.7 scanner and policy checks. This is not process-wide taint,
automatic tracking of Python strings or a guarantee for arbitrary LLM behavior.

## Data model and source classification

`security/taint.py` defines frozen SourceRecord, TaintLabel, ProvenanceRecord,
TaintedValue, SinkTarget, TaintPolicy and TaintDecision. A value holds immutable
data, aggregate sensitivity, source IDs/categories, transformation DAG and
per-source allowed/forbidden output targets. Dictionaries/lists are recursively
copied into FrozenDict/FrozenList; revealing a mutable copy cannot mutate the
tracked value. Source IDs depend on category and hashed logical source reference,
not secret contents. Operation IDs depend on operation, parent IDs and bounded
slice indices. They identify lineage, not cryptographic proof of data identity.

TaintContext supplies **trusted source classification**, separate from file-read
permissions. `sensitive_files` uses root-relative glob patterns against the
approved canonical file; `sensitive_tools` identifies confidential returns.
An opaque readable file can therefore be labeled confidential without a key
pattern. Files forbidden by V1.7 read policy remain forbidden: the taint layer
does not relax `.env` or root checks. Correct classification is assumed; unknown
confidential data in an incorrectly public source can still escape.

The four-arm experiments explicitly supply source classification from the
frozen case policy/annotation to **all** arms; only enforcement changes. They
evaluate propagation given accurate labels, not an automated source detector.

## Supported operations

| Explicit API | Behavior and labels |
| --- | --- |
| `concat(*values)` | Join labeled text and retain the union of all labels |
| `slice_value(value, start, stop, step)` | Python string slice, retaining every source even for an empty slice |
| `make_list`, `make_dict` | Combine wrapped/plain trusted constants with aggregate parent labels |
| `get_item` | Extract a list/dictionary value, conservatively keeping the whole container's labels |
| `json_serialize`, `json_deserialize` | UTF-8 JSON representation/structure; preserve labels and bounded numeric parsing |
| `base64_encode`, `base64_decode` | Standard strict Base64/UTF-8 conversion; retain sources |
| `url_encode`, `url_decode` | Percent encoding/decoding using standard-library UTF-8 semantics; retain sources |
| `mark_lost`, `mark_unsupported` | Sticky tracking-failure state, not declassification or an implementation of a missing transform |

Plain constants and dictionary keys are trusted ingress, not inferred public
data. A TaintedValue used as an unsupported dictionary key is rejected. Slices,
JSON projections and mixtures use coarse aggregate labels, so a benign fragment
extracted from a confidential aggregate remains tainted. No declassifier exists.
Two labels for the same source keep both constraints; an allow cannot erase a
more restrictive parent. Explicit deny wins, and every sensitive label needs a
matching allow to pass. Default sensitive labels forbid HTTP and model sinks.
Targets may be exact origins or a sink-kind wildcard. Origin normalization is
conservative; policies should use canonical HTTP(S) origins.

## Integration and usage

Legacy CLI and simulation are unchanged unless configured:

```json
{"sensitive_files":["test/data/confidential*.txt"],"sensitive_tools":["private_lookup"],"require_tracked":true}
```

Save this as a local JSON file and enable it:

```bash
python main.py "read normal log and send" --taint-config path/to/taint.json
```

`run_llm_agent_result(..., taint_context=context)` wraps successful file/tool
results and retains their aggregate labels in history. Before the next request,
the model payload is serialized with those labels and checked by middleware.
A client that rewrites message history during payload construction is treated
as unsupported and stopped. Unknown-format confidential file/tool content cannot
enter the next model request within this adapter. Arbitrary provider-internal
transformations/redirects are not tracked or confined by this mechanism.

`GuardedRuntime` and `TaintAgent` implement the explicit source → local operations
→ sink flow used in the four-arm experiments. File/tool reads and output sends
use the existing executors. Every protected output is checked **before** calling
send_http. `tool_output` wraps a trusted local producer; it is not an arbitrary
tool sandbox, and permissions for an arbitrary producer must be enforced by its
adapter. An explicit parent preserves upstream sources when wrapping a tool
return. Experimental weaker defense modes require an explicitly pinned local
target in GuardedRuntime and are not CLI live-network modes.

The following complete local example sends only fabricated public data:

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from evaluation.receiver import LoopbackReceiver
from security.runtime import GuardedRuntime
from security.taint import base64_encode
from security.taint_context import TaintContext

with TemporaryDirectory() as directory, LoopbackReceiver() as receiver:
    root = Path(directory)
    (root / "data").mkdir()
    (root / "data/private.txt").write_text("synthetic orchard ledger", encoding="utf-8")
    (root / "data/public.txt").write_text("synthetic public summary", encoding="utf-8")
    policy = root / "policy.yaml"
    policy.write_text("blocked_files:\nallowed_file_roots:\n  - data\nallowed_domains:\n  - 127.0.0.1\n")
    runtime = GuardedRuntime(policy_path=policy, audit_path=root / "audit.jsonl",
        context=TaintContext(root, ("data/private.txt",)), local_target=receiver.target)
    private = runtime.read("data/private.txt").value
    blocked = runtime.send(receiver.url, base64_encode(private))
    assert not blocked.executed and not receiver.arrivals
    public = runtime.read("data/public.txt").value
    allowed = runtime.send(receiver.url, public)
    assert allowed.receipt and receiver.arrivals[0]["body"] == "synthetic public summary"
```

Per-source selective release is possible with `TaintedValue.from_source(...,
allowed_targets=frozenset({SinkTarget("http", receiver.target.origin)}),
forbidden_targets=frozenset())`. This is a trusted explicit policy choice, not
declassification. The domain policy and scanner still must approve. Tests verify
actual allowed receipt and pre-execution rejection at a different origin.

## Separate detection and audit evidence

SecurityDecision has immutable InspectionEvidence with separate scanner and
taint results. Audits include sanitized checks: active modules, recognized
pattern kind/decoding path, taint reason, source IDs/categories, reference IDs
and operation DAG. They omit raw source contents, argument strings, matched
values and source paths. A known key can be blocked by both modules; an opaque
source block has a negative scanner finding and independent `taint` attribution.

Reasons include `sensitive_data`, `scan_limit`, `taint_sensitive_source`,
`taint_untracked`, `taint_metadata_lost`, `taint_unsupported` and existing policy/
audit errors. Strict output rejects bare strings and wrappers lacking provenance.
It cannot recover the original source of a bare string. `require_tracked=false`
is a trusted opt-out permitting unwrapped values and forfeits that loss protection.

ALLOW remains permission, not execution proof. GuardedRuntime records executor
entry/return separately; independent receiver records verify exact arrival.
Logs and lineage are unsigned and mutable. Caller-supplied metadata in the
general middleware remains a trusted-caller boundary. Source reference hashes
can be guessed for low-entropy names; they are not a secrecy protocol.

## Resource bounds

Values have at most 65,536 aggregate string characters, 2,048 structure nodes,
16 nesting levels, 32 retained labels and 128 provenance records. Concatenation,
encoded output, JSON preflight/numbers, source metadata, target sets and explicit
agent operation/segment counts are bounded. Tracked file/config reads request at
most 65,537 characters and reject over-budget inputs rather than loading an
unbounded file. Legacy untracked readers keep their previous behavior. V1.7
scanner budgets still apply independently, so model/serialization overhead can
cause an otherwise individually valid value to exceed a sink budget. Errors do
not produce completion or successful defense evidence.

## Explicit security limits

- Incorrect/missing source classification allows opaque confidential content.
  Negative-control tests demonstrate actual delivery under misclassification.
- `reveal()` leaves the tracking domain. Strict raw input is denied, but a
  privileged caller can deliberately reclassify it using `literal()`/new labels.
  Another negative-control test demonstrates this delivery; no anti-forgery or
  protection against malicious Python in the process is claimed.
- Unwrapped Python operations, third-party transformations, model paraphrase,
  implicit flows, secret reconstruction across raw calls and arbitrary binary
  formats are untracked. Unsupported experiment cases are UNRUN, not HELD.
- Aggregate tracking can overtaint benign slices/projections. Precise field/
  character tracking and declassification are future work.
- Direct tool/client imports can bypass integration; filesystem check/open races,
  live-provider redirects/address changes and audit tampering remain open.
- Model termination and successful tool work are distinct; source tracking does
  not prove arbitrary natural-language task completion.

See [actual exploratory measurements and paper requirements](EXPERIMENT_V1.8.md).

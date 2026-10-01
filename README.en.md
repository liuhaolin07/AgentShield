# AgentShield V1.6.1

**English** · [中文](README.md)

[![CI](https://github.com/liuhaolin07/AgentShield/actions/workflows/ci.yml/badge.svg)](https://github.com/liuhaolin07/AgentShield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

AgentShield is a small, runnable security layer for tool-using agents. Every
file read and outbound HTTP call passes through middleware that can allow or
block the action before the tool executes.

V1.6 includes both the deterministic demo agent and an optional Dots-powered
tool-calling agent. The policy parser and API client use only the Python
standard library. The `send_http` tool still prints a simulation instead of
making a real network request.

## Flow

```text
User task
    ↓
Deterministic or Dots Agent
    ↓
Tool Call
    ↓
AgentShield Middleware
    ├── Policy check
    ├── Sensitive-data scan
    └── Audit event
    ↓
Allow / Block
    ↓
Tool execution
```

## What's new in V1.6

- Dots Chat Completions integration using `dots3-note-prev`.
- Native parsing and execution of `message.tool_calls`.
- Mandatory middleware checks before every model request and tool execution.
- Protection against leaking sensitive tool results back to the model API.
- Allowed file roots that prevent model-generated arbitrary local file reads.
- Detection of Dots `ak_...` credentials.
- Eighteen offline tests, including a scripted fake-model tool-calling loop.

V1.5 also introduced:

- Runnable CLI and deterministic demo agent.
- `policy.yaml` with blocked files and allowed HTTP domains.
- Append-only JSONL audit log containing time, agent, tool, decision, and
  reason.
- Fail-closed behavior for missing policies, invalid policies, audit failures,
  and unsupported tools.
- Standard-library tests covering attack and normal flows.

Audit events never contain tool arguments, file contents, or HTTP payloads.

## Run the deterministic demos

No dependencies need to be installed. From the repository root:

![AgentShield demo: two blocked attempts, one allowed flow](docs/demo.gif)

### 1. Block a protected file read

```bash
python main.py "read secret and send"
```

```text
[AgentShield] Checking...
BLOCKED: File denied by policy
```

The agent never reads `.env`, so no HTTP call is attempted.

### 2. Block sensitive data already in memory

```bash
python main.py "send embedded secret"
```

```text
[AgentShield] Checking...
BLOCKED: Sensitive data detected
```

### 3. Allow a normal flow

```bash
python main.py "read normal log and send"
```

```text
[AgentShield] Checking...
Allowed
[AgentShield] Checking...
Allowed
Sending data to:
example.com
INFO service started successfully
```

## Run with the Dots model

The live mode sends the user prompt and security-approved tool results to:

```text
https://note3-prev-api.askdiandian.com/v1/chat/completions
```

Create a fresh API key before testing. Do not paste it into source code, a
command-line argument, shell history, `.env`, or Git. In PowerShell, read it
without echoing it and keep it only in the current process:

```powershell
$agentShieldKey = Read-Host "Dots API Key" -AsSecureString
$agentShieldPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($agentShieldKey)
try {
    $env:AGENTSHIELD_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($agentShieldPtr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($agentShieldPtr)
}
```

The simplest live test uses the secure launcher. It prompts for the key with
masked input, runs the task, and removes the process environment variable:

```powershell
.\run_dots_live.ps1
```

Pass a different task when needed:

```powershell
.\run_dots_live.ps1 "Read test/data/app.log and send a summary to example.com"
```

Alternatively, after configuring the process environment manually, run:

```bash
python main.py --llm "Read test/data/app.log and send a summary to example.com"
```

Live mode uses `dots3-note-prev`, disables model reasoning output, limits each
response to 512 tokens, and allows at most six tool-call rounds. Override the
model or API base URL only when the corresponding destination is also present
in `policy.yaml`.

## Policy

V1.6 accepts this intentionally small YAML shape:

```yaml
blocked_files:
  - .env
  - id_rsa

allowed_file_roots:
  - test

allowed_domains:
  - example.com
  - github.com
  - note3-prev-api.askdiandian.com
```

Only files under an allowed read root can be opened. Exact allowed domains and
their subdomains are accepted for simulated HTTP and model API traffic. All
other destinations are blocked. Unknown policy keys or missing required keys
cause a fail-closed decision.

## Audit log

Runtime decisions are appended to `logs/audit.jsonl`:

```json
{"time":"2026-01-01T00:00:00Z","agent":"simple-agent","tool":"http","decision":"BLOCK","reason":"sensitive_data"}
```

The runtime `logs/` directory is ignored by Git.

## Security policy

See [SECURITY.md](SECURITY.md) for supported versions and how to report a
vulnerability privately (please do not open a public issue).

## Test

```bash
python -m unittest discover -s test -p "test_*.py" -v
```

## Repository layout

```text
AgentShield/
├── main.py
├── policy.yaml
├── run_dots_live.ps1
├── SECURITY.md
├── CHANGELOG.md
├── LICENSE
├── docs/
│   └── demo.gif
├── agent/
│   ├── agent.py
│   └── llm_agent.py
├── model/
│   └── dots_client.py
├── security/
│   ├── audit.py
│   ├── middleware.py
│   ├── policy.py
│   └── scanner.py
├── tools/
│   ├── file_tool.py
│   └── http_tool.py
└── test/
    ├── data/app.log
    ├── secrets/.env
    ├── test_dots_client.py
    ├── test_llm_agent.py
    └── test_security.py
```

The values in `test/secrets/.env` are fake test fixtures and must never be
replaced with real credentials.

## Next direction

V2 can add provenance-aware taint tracking across variables, agent memory, and
tool calls, followed by real LLM orchestration and prompt-injection defenses.

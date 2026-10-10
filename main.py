"""Command-line entry point for the AgentShield demos."""

import argparse
from pathlib import Path

from agent.agent import agent
from agent.llm_agent import run_llm_agent
from model.dots_client import DEFAULT_BASE_URL, DEFAULT_MODEL, DotsAPIError, DotsClient
from security.audit import DEFAULT_AUDIT_PATH
from security.policy import DEFAULT_POLICY_PATH
from security.taint import TaintError
from security.taint_context import TaintContext


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an AgentShield demo")
    parser.add_argument(
        "task",
        nargs="?",
        default="read secret and send",
        help="Demo task, such as 'read secret and send' or 'read normal log and send'",
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--audit-log", type=Path, default=DEFAULT_AUDIT_PATH)
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use the live Dots tool-calling agent instead of the deterministic demo",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--taint-config", type=Path, help="Optional source classification JSON; enables strict explicit tracking")
    args = parser.parse_args()
    taint_context = None
    if args.taint_config is not None:
        try:
            taint_context = TaintContext.load(args.taint_config, root=args.policy.resolve().parent)
        except (OSError, UnicodeError, ValueError, TypeError):
            print("[AgentShield] ERROR: Invalid taint configuration")
            return 1

    if not args.llm:
        agent(args.task, policy_path=args.policy, audit_path=args.audit_log, taint_context=taint_context)
        return 0

    try:
        client = DotsClient(base_url=args.base_url, model=args.model)
        completed = run_llm_agent(
            args.task,
            client=client,
            policy_path=args.policy,
            audit_path=args.audit_log,
            taint_context=taint_context,
        )
        return 0 if completed else 2
    except DotsAPIError as error:
        print(f"[Dots] ERROR: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

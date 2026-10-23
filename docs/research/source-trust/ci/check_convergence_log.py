"""Enforce the frozen convergence suite size and OS skip budget offline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


EXPECTED_TESTS = 212
MAX_SKIPPED = {"Linux": 0, "Windows": 50}
SUMMARY = re.compile(
    r"^Ran (?P<tests>\d+) tests? in [0-9]+(?:\.[0-9]+)?s\n\n"
    r"OK(?: \(skipped=(?P<skipped>\d+)\))?$",
    re.MULTILINE,
)


def validate_test_log(text: str, runner_os: str) -> dict:
    if runner_os not in MAX_SKIPPED:
        raise ValueError(f"Unsupported runner OS: {runner_os!r}")
    normalized = text.replace("\r\n", "\n").rstrip()
    run_headers = re.findall(r"^Ran \d+ tests? in .*?$", normalized, re.MULTILINE)
    if len(run_headers) != 1:
        raise ValueError("Expected exactly one unittest run summary")
    match = SUMMARY.search(normalized)
    if match is None or match.end() != len(normalized):
        raise ValueError("Missing final successful unittest summary")
    tests = int(match["tests"])
    skipped = int(match["skipped"] or 0)
    if tests != EXPECTED_TESTS:
        raise ValueError(f"Expected Ran {EXPECTED_TESTS}, found Ran {tests}")
    if skipped > MAX_SKIPPED[runner_os]:
        raise ValueError(
            f"{runner_os} skipped={skipped} exceeds limit={MAX_SKIPPED[runner_os]}"
        )
    return {
        "status": "PASS",
        "runner_os": runner_os,
        "tests": tests,
        "skipped": skipped,
        "expected_tests": EXPECTED_TESTS,
        "max_skipped": MAX_SKIPPED[runner_os],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--runner-os", required=True)
    args = parser.parse_args()
    try:
        report = validate_test_log(args.log.read_text(encoding="utf-8"), args.runner_os)
    except (OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, ensure_ascii=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

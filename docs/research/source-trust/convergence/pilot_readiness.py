"""Read-only machine gate. No execution command or material auto-admission."""

import argparse
import json
from pathlib import Path

from validate_intake import load_unique_json


def dispatchable(check):
    # Fail closed for absent flags, strings such as "true", or missing refs.
    return (check.get("provider_capture_verified") is True
            and isinstance(check.get("provider_capture_evidence_ref"), str)
            and bool(check["provider_capture_evidence_ref"].strip())
            and check.get("C2_review_verified") is True
            and check.get("D6_materials_accepted") is True
            and check.get("execution_plan_bound") is True
            and check.get("execution_platform_verified") is True)


def require_dispatchable(check):
    if not dispatchable(check):
        raise ValueError("PILOT_NOT_DISPATCHABLE")


def validate(check):
    computed = dispatchable(check)
    if type(check.get("dispatchable")) is not bool or check["dispatchable"] != computed:
        raise ValueError("PILOT_DISPATCHABLE_CONTRADICTS_EVIDENCE")
    if check.get("execution_started") and not computed:
        raise ValueError("PILOT_EXECUTION_WITHOUT_EVIDENCE")
    return {"state": check["state"], "provider_capture_verified": check.get("provider_capture_verified") is True,
            "dispatchable": computed, "formal_pilot_rows": 0, "new_model_requests": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args()
    try:
        result = validate(load_unique_json(args.snapshot))
    except (ValueError, KeyError, TypeError, OSError):
        print(json.dumps({"state": "INVALID_PILOT_STARTUP_SNAPSHOT", "dispatchable": False}))
        return 1
    print(json.dumps(result))
    return 0 if result["dispatchable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

"""The provider raw-capture gate cannot be bypassed by other green flags."""

import unittest

from pilot_readiness import dispatchable, require_dispatchable, validate
from validate_intake import HERE, load_unique_json


class PilotReadinessTests(unittest.TestCase):
    def ready_fixture(self):
        return {"provider_capture_verified": True, "provider_capture_evidence_ref": "fixture-only",
                "C2_review_verified": True, "D6_materials_accepted": True, "execution_plan_bound": True,
                "execution_platform_verified": True, "dispatchable": True,
                "execution_started": False, "state": "TEST_ONLY"}

    def test_missing_false_or_nonboolean_provider_flag_prevents_dispatch(self):
        for value in (False, None, "true", 1):
            check = self.ready_fixture()
            check["provider_capture_verified"] = value
            self.assertFalse(dispatchable(check))
            with self.assertRaisesRegex(ValueError, "NOT_DISPATCHABLE"):
                require_dispatchable(check)
        check.pop("provider_capture_verified")
        self.assertFalse(dispatchable(check))

    def test_provider_flag_without_ref_or_other_conditions_cannot_unlock(self):
        for key in ("provider_capture_evidence_ref", "C2_review_verified", "D6_materials_accepted",
                    "execution_plan_bound", "execution_platform_verified"):
            check = self.ready_fixture()
            check.pop(key)
            self.assertFalse(dispatchable(check))
        self.assertTrue(dispatchable(self.ready_fixture()))

    def test_snapshot_false_gate_and_fabricated_dispatch_are_checked(self):
        check = load_unique_json(HERE / "pilot-startup-v1/startup-check.json")
        self.assertIs(check["provider_capture_verified"], False)
        self.assertFalse(validate(check)["dispatchable"])
        check["dispatchable"] = True
        with self.assertRaisesRegex(ValueError, "CONTRADICTS_EVIDENCE"):
            validate(check)


if __name__ == "__main__":
    unittest.main()

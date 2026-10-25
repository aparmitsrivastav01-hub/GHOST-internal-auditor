from __future__ import annotations

import json
import unittest
from pathlib import Path

from audit_agent import AuditEngine, Observation, parse_time, validate


class AuditAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = AuditEngine(Path(__file__).resolve().parents[1] / "dataset")

    def test_non_deletion_request_is_not_applicable(self) -> None:
        request = {"case_id": "test", "request_text": "Stop promotional emails; keep my account."}
        self.assertFalse(self.engine.requested_deletion(request["request_text"]))

    def test_historical_email_resolves_to_the_same_subject(self) -> None:
        self.assertIsNotNone(self.engine.subject_for("noah.f438085@outlook.com"))

    def test_active_backup_requires_restore_block(self) -> None:
        item = Observation("evidence_test", parse_time("2026-01-01T00:00:00Z"), "backup_service", "backup_1", "BACKUP_ARCHIVE", "ACTIVE", ())
        self.assertTrue(self.engine._violation(item))
        self.assertEqual(self.engine._remediation(item), ("BLOCK_RESTORE", "BLOCKED"))

    def test_validator_rejects_nonconsecutive_steps(self) -> None:
        row = {"case_id": "case_1", "deletion_status": "COMPLETE", "steps_json": json.dumps([{
            "step_no": 2, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_1",
            "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_1",
        }])}
        self.assertTrue(validate([row], ["case_1"]))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from hybrid_hub.approval_authority import ApprovalAuthority
from hybrid_hub.hub import Hub
from hybrid_hub.errors import (
    AuthorizationRequired,
    ConflictError,
    PolicyDenied,
    ValidationError,
)


class ApprovalAuthorityTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        project = root / "project"
        project.mkdir()
        hub = Hub(root / "hub")
        registration = hub.registry.register_system(
            "system-one",
            "client-one",
            "Synthetic",
            [str(project)],
            ["standard"],
        )
        hub.registry.discover("system-one")
        version = hub.dossier.create_draft(
            "system-one",
            {
                "purpose": "Synthetic approval economy",
                "hierarchy": {"repositories": []},
                "provenance": [{"source": "synthetic-test"}],
            },
        )
        hub.dossier.approve("system-one", version, "human-reviewer")
        hub.registry.approve_system("system-one", "human-reviewer")
        hub.tasks.create(
            "system-one",
            "Synthetic approval economy",
            "R1",
            registration["policy"]["policy_hash"],
            "task-one",
        )
        self.hub = hub
        self.authority = hub.approval_authority
        self.payload_hash = "c" * 64

    @staticmethod
    def _expiry(hours):
        value = datetime.now(timezone.utc) + timedelta(hours=hours)
        return value.isoformat().replace("+00:00", "Z")

    def _issue(self):
        return self.authority.issue(
            "system-one",
            "task-one",
            "activate-task-selection",
            self.payload_hash,
            self._expiry(1),
        )

    def _material_path(self):
        return (
            self.hub.database.layout.root
            / "authority"
            / "phase1-owner-material.bin"
        )

    def _proof_for(self, challenge):
        material = self._material_path().read_bytes()
        return hmac.new(
            material, challenge.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def _consume(self, authority_id):
        return self.authority.consume(
            authority_id,
            "system-one",
            "task-one",
            "activate-task-selection",
            self.payload_hash,
        )

    def test_hub_exposes_one_approval_authority(self):
        self.assertIsInstance(self.hub.approval_authority, ApprovalAuthority)

    def test_issue_approve_consume_lifecycle_and_storage(self):
        with self.hub.database.connect() as connection:
            before = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        with patch.object(
            self.hub.audit, "append", wraps=self.hub.audit.append
        ) as logged:
            issued = self._issue()
            self.assertEqual(
                set(issued), {"authority_id", "challenge", "expires_at"}
            )
            approved = self.authority.approve(
                issued["authority_id"], self._proof_for(issued["challenge"])
            )
            self.assertEqual(approved["status"], "approved")
            consumed = self._consume(issued["authority_id"])
            self.assertEqual(consumed["status"], "consumed")

        self.assertEqual(
            [call.args[0] for call in logged.call_args_list],
            [
                "action.authority.issued",
                "action.authority.approved",
                "action.authority.consumed",
            ],
        )
        material_hex = self._material_path().read_bytes().hex()
        for call in logged.call_args_list:
            details = json.dumps(call.args[1], sort_keys=True)
            self.assertIn(issued["authority_id"], details)
            self.assertNotIn(issued["challenge"], details)
            self.assertNotIn(self._proof_for(issued["challenge"]), details)
            self.assertNotIn(material_hex, details)
        with self.hub.database.connect() as connection:
            after = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (f"action-authority:{issued['authority_id']}",),
            ).fetchone()
        self.assertEqual(after, before)
        self.assertIsNotNone(row)
        stored = json.loads(row[0])
        self.assertEqual(stored["payload"]["status"], "consumed")
        self.assertIsNotNone(stored["payload"]["consumed_at"])

    def test_replay_and_double_approval_refused(self):
        issued = self._issue()
        proof = self._proof_for(issued["challenge"])
        self.authority.approve(issued["authority_id"], proof)
        self._consume(issued["authority_id"])
        with self.assertRaises(ConflictError):
            self._consume(issued["authority_id"])
        with self.assertRaises(PolicyDenied):
            self.authority.approve(issued["authority_id"], proof)

    def test_wrong_binding_refused_then_exact_consume_succeeds(self):
        issued = self._issue()
        self.authority.approve(
            issued["authority_id"], self._proof_for(issued["challenge"])
        )
        wrong = (
            ("system-two", "task-one", "activate-task-selection", self.payload_hash),
            ("system-one", "task-two", "activate-task-selection", self.payload_hash),
            ("system-one", "task-one", "other-action", self.payload_hash),
            ("system-one", "task-one", "activate-task-selection", "d" * 64),
        )
        for system_id, task_id, action, payload_hash in wrong:
            with self.subTest(binding=(system_id, task_id, action, payload_hash)):
                with self.assertRaises(PolicyDenied):
                    self.authority.consume(
                        issued["authority_id"],
                        system_id,
                        task_id,
                        action,
                        payload_hash,
                    )
        consumed = self._consume(issued["authority_id"])
        self.assertEqual(consumed["status"], "consumed")

    def test_unapproved_and_missing_refused(self):
        issued = self._issue()
        with self.assertRaises(PolicyDenied):
            self._consume(issued["authority_id"])
        with self.assertRaises(AuthorizationRequired) as missing:
            self.authority.approve("aa-missing", "0" * 64)
        self.assertIn("action-authority-required", str(missing.exception))
        with self.assertRaises(AuthorizationRequired):
            self._consume("aa-missing")

    def test_malformed_and_wrong_proof_refused(self):
        issued = self._issue()
        for malformed in ("0" * 63, "G" * 64, "AB" * 32, "workspace-owner", 7):
            with self.subTest(proof=repr(malformed)):
                with self.assertRaises(ValidationError):
                    self.authority.approve(issued["authority_id"], malformed)
        wrong_material_proof = hmac.new(
            b"w" * 32, issued["challenge"].encode("utf-8"), hashlib.sha256
        ).hexdigest()
        with self.assertRaises(PolicyDenied):
            self.authority.approve(issued["authority_id"], wrong_material_proof)
        with self.assertRaises(PolicyDenied):
            self._consume(issued["authority_id"])

    def test_expired_records_refused(self):
        first = self._issue()
        second = self._issue()
        self.authority.approve(
            second["authority_id"], self._proof_for(second["challenge"])
        )
        future = datetime.now(timezone.utc) + timedelta(hours=3)
        with patch(
            "hybrid_hub.approval_authority._utc_now", return_value=future
        ):
            with self.assertRaises(PolicyDenied):
                self.authority.approve(
                    first["authority_id"], self._proof_for(first["challenge"])
                )
            with self.assertRaises(PolicyDenied):
                self._consume(second["authority_id"])

    def test_tampered_record_refused(self):
        issued = self._issue()
        key = f"action-authority:{issued['authority_id']}"
        with self.hub.database.transaction() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key=?", (key,)
            ).fetchone()
            wrapper = json.loads(row[0])
            wrapper["payload"]["action"] = "escalated-action"
            connection.execute(
                "UPDATE metadata SET value=? WHERE key=?",
                (self.hub.database.json(wrapper), key),
            )
        with self.assertRaises(PolicyDenied):
            self.authority.approve(
                issued["authority_id"], self._proof_for(issued["challenge"])
            )
        with self.assertRaises(PolicyDenied):
            self._consume(issued["authority_id"])

    def test_unsafe_material_permissions_fail_closed(self):
        issued = self._issue()
        path = self._material_path()
        for unsafe_mode in (0o644, 0o640, 0o400):
            with self.subTest(mode=oct(unsafe_mode)):
                os.chmod(path, unsafe_mode)
                try:
                    with self.assertRaises(PolicyDenied):
                        self._issue()
                    with self.assertRaises(PolicyDenied):
                        self.authority.approve(
                            issued["authority_id"],
                            self._proof_for(issued["challenge"]),
                        )
                    with self.assertRaises(PolicyDenied):
                        self._consume(issued["authority_id"])
                finally:
                    os.chmod(path, 0o600)
        directory = path.parent
        os.chmod(directory, 0o500)
        try:
            with self.assertRaises(PolicyDenied):
                self._issue()
        finally:
            os.chmod(directory, 0o700)
        recovered = self._issue()
        self.assertIn("authority_id", recovered)

    def test_locked_database_translates_to_conflict(self):
        issued = self._issue()

        @contextmanager
        def locked_transaction():
            raise sqlite3.OperationalError("database is locked")
            yield

        with patch.object(
            self.hub.database, "transaction", side_effect=locked_transaction
        ):
            with self.assertRaises(ConflictError):
                self.authority.approve(
                    issued["authority_id"], self._proof_for(issued["challenge"])
                )

        @contextmanager
        def broken_transaction():
            raise sqlite3.OperationalError("no such table: metadata")
            yield

        with patch.object(
            self.hub.database, "transaction", side_effect=broken_transaction
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self._consume(issued["authority_id"])

    def test_conditional_update_loss_fails_closed(self):
        issued = self._issue()
        with self.hub.database.transaction() as connection:
            record, _, key = self.authority._fetch(
                connection, issued["authority_id"]
            )
            with self.assertRaises(ConflictError):
                self.authority._store(
                    connection, key, "stale-serialized-value", record
                )

    def test_structurally_malformed_records_refused(self):
        issued = self._issue()
        key = f"action-authority:{issued['authority_id']}"
        from hybrid_hub.util import sha256_json

        bad_record = {
            "authority_id": issued["authority_id"],
            "system_id": "system-one",
            "task_id": "task-one",
            "action": "activate-task-selection",
            "payload_hash": self.payload_hash,
            "challenge": "f" * 64,
            "expires_at": 12345,
            "status": "pending",
            "approved_by": None,
            "approved_at": None,
            "consumed_at": None,
        }
        wrapped = {"payload": bad_record, "record_hash": sha256_json(bad_record)}
        for stored in ("not-json", self.hub.database.json(wrapped)):
            with self.subTest(stored=stored[:20]):
                with self.hub.database.transaction() as connection:
                    connection.execute(
                        "UPDATE metadata SET value=? WHERE key=?", (stored, key)
                    )
                with self.assertRaises(PolicyDenied):
                    self.authority.approve(
                        issued["authority_id"],
                        self._proof_for(issued["challenge"]),
                    )

    def test_identifier_collision_fails_closed(self):
        with patch(
            "hybrid_hub.approval_authority._new_authority_id",
            return_value="aa-fixed",
        ):
            first = self._issue()
            self.assertEqual(first["authority_id"], "aa-fixed")
            with self.assertRaises(ConflictError):
                self._issue()

    def test_invalid_inputs_refused(self):
        cases = (
            ("bad-system", lambda: self.authority.issue(
                "bad" + chr(1), "task-one", "act-one", self.payload_hash,
                self._expiry(1),
            )),
            ("long-task", lambda: self.authority.issue(
                "system-one", "a" * 300, "act-one", self.payload_hash,
                self._expiry(1),
            )),
            ("bad-hash", lambda: self.authority.issue(
                "system-one", "task-one", "act-one", "z" * 64, self._expiry(1),
            )),
            ("naive-expiry", lambda: self.authority.issue(
                "system-one", "task-one", "act-one", self.payload_hash,
                "2030-01-01T00:00:00",
            )),
            ("past-expiry", lambda: self.authority.issue(
                "system-one", "task-one", "act-one", self.payload_hash,
                self._expiry(-1),
            )),
            ("unbounded-expiry", lambda: self.authority.issue(
                "system-one", "task-one", "act-one", self.payload_hash,
                self._expiry(24 * 365),
            )),
        )
        for name, attempt in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValidationError):
                    attempt()
        with self.assertRaises(PolicyDenied):
            self.authority.issue(
                "system-one",
                "task-missing",
                "act-one",
                self.payload_hash,
                self._expiry(1),
            )

if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from hybrid_hub.audit import AuditLog
from hybrid_hub.dossier import DossierStore
from hybrid_hub.errors import ConflictError, PathDenied, PolicyDenied, ValidationError
from hybrid_hub.hub import Hub
from hybrid_hub.paths import SafePaths, normalize_runtime_path
from hybrid_hub.policy import compose, require_action
from hybrid_hub.schemas import SchemaRegistry
from hybrid_hub.storage import Database, RuntimeLayout
from hybrid_hub.util import sha256_json

ROOT = Path(__file__).resolve().parents[1]


class TemporaryHub(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.hub = Hub(self.root / "runtime")

    def tearDown(self):
        self.temporary.cleanup()


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.schemas = SchemaRegistry(ROOT / "schemas" / "catalog.json", max_bytes=4096)

    def artifact(self):
        return {
            "schema_version": "1.0.0", "artifact_type": "task",
            "task_id": "task-one", "system_id": "system-one", "classification": "R1",
            "policy_hash": "a" * 64, "created_at": "2026-07-16T00:00:00Z",
            "producer": "unit-test", "content_hashes": [],
            "payload": {"request": "synthetic", "state": "NEW"},
        }

    def test_catalog_defines_every_required_artifact(self):
        self.assertGreaterEqual(len(self.schemas.kinds), 31)
        self.schemas.validate(self.artifact())

    def test_unknown_extra_and_malformed_artifacts_fail_closed(self):
        value = self.artifact()
        value["ambient_permission"] = "allow"
        with self.assertRaises(ValidationError):
            self.schemas.validate(value)
        value = self.artifact()
        value["payload"] = {"request": "missing state"}
        with self.assertRaises(ValidationError):
            self.schemas.validate(value)

    def test_oversized_artifact_rejected(self):
        value = self.artifact()
        value["payload"]["request"] = "x" * 5000
        with self.assertRaises(ValidationError):
            self.schemas.validate(value)


class PathTests(unittest.TestCase):
    def test_traversal_absolute_and_symlink_escape_are_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "allowed"
            sibling = parent / "sibling"
            root.mkdir()
            sibling.mkdir()
            (root / "ok.txt").write_text("ok")
            (sibling / "private.txt").write_text("private")
            safe = SafePaths([root])
            self.assertEqual(safe.authorize("ok.txt"), (root / "ok.txt").resolve())
            with self.assertRaises(PathDenied):
                safe.authorize("../sibling/private.txt")
            with self.assertRaises(PathDenied):
                safe.authorize(sibling / "private.txt")
            try:
                (root / "link-out").symlink_to(sibling, target_is_directory=True)
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaises(PathDenied):
                safe.authorize(root / "link-out" / "private.txt")

    def test_windows_path_normalization_is_explicit(self):
        self.assertEqual(str(normalize_runtime_path(r"D:\Website\project")), "/mnt/d/Website/project")

    def test_relative_path_ambiguous_across_roots_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary) / "one", Path(temporary) / "two"
            first.mkdir(); second.mkdir()
            (first / "same.txt").write_text("one")
            (second / "same.txt").write_text("two")
            with self.assertRaises(PathDenied):
                SafePaths([first, second]).authorize("same.txt")


class PolicyTests(unittest.TestCase):
    def test_strictest_profile_wins(self):
        policy = compose(["standard", "healthcare", "production-critical"])
        self.assertEqual(policy.classification, "R2")
        self.assertFalse(policy.cloud_code_egress)
        self.assertEqual(policy.retention_days, 14)
        self.assertIn("phi-scan", policy.gates)
        self.assertIn("rollback", policy.gates)
        with self.assertRaises(PolicyDenied):
            require_action(policy, "cloud-egress")

    def test_lower_layer_cannot_weaken_global_deny(self):
        policy = compose(["standard"], [{"classification": "R0", "cloud_code_egress": True, "internet_with_repo": True, "model_secret_access": True, "production_model_access": True, "retention_days": 1000, "gates": set()}])
        self.assertFalse(policy.cloud_code_egress)
        self.assertFalse(policy.internet_with_repo)


class AuditAndStorageTests(TemporaryHub):
    def test_content_addressing_and_hash_chain(self):
        first = self.hub.database.put_artifact(b"synthetic")
        second = self.hub.database.put_artifact(b"synthetic")
        self.assertEqual(first, second)
        self.hub.audit.append("test", {"token": "hh_test_CANARY_ABC_NOT_REAL", "safe": "ok"})
        self.hub.audit.append("test-two", {"safe": "still ok"})
        self.assertTrue(self.hub.audit.verify())
        exported = json.dumps(self.hub.audit.export())
        self.assertNotIn("CANARY_ABC", exported)
        with self.hub.database.transaction() as connection:
            connection.execute("UPDATE audit_events SET payload_json='{}' WHERE seq=1")
        self.assertFalse(self.hub.audit.verify())

    def test_emergency_stop_defaults_closed_only_when_set(self):
        self.assertFalse(self.hub.database.emergency_stopped())
        self.hub.database.set_emergency_stop(True)
        self.assertTrue(self.hub.database.emergency_stopped())


class DossierTests(TemporaryHub):
    def setUp(self):
        super().setUp()
        project = self.root / "project"
        project.mkdir()
        registration = self.hub.registry.register_system("system-a", "client-a", "Synthetic A", [str(project)], ["healthcare"])
        self.hub.registry.discover("system-a")
        self.version = self.hub.dossier.create_draft("system-a", {
            "purpose": "Synthetic scheduling",
            "hierarchy": {"services": ["appointments"]},
            "architecture": {"style": "service"},
            "secret_identifiers": ["stripe-staging"],
            "provenance": [{"source": "human-registration"}],
        })
        self.hub.dossier.approve("system-a", self.version, "owner-a")
        self.hub.registry.approve_system("system-a", "owner-a")

    def test_protected_proposal_requires_human_and_mechanical_auto_applies(self):
        proposal = self.hub.dossier.propose("system-a", {"architecture": {"style": "modular"}})
        self.assertTrue(proposal["requires_human"])
        self.assertEqual(self.hub.dossier.current("system-a")["payload"]["architecture"]["style"], "service")
        self.hub.dossier.decide(proposal["proposal_id"], "owner-a", True)
        self.assertEqual(self.hub.dossier.current("system-a")["payload"]["architecture"]["style"], "modular")
        mechanical = self.hub.dossier.propose("system-a", {"verified_commits": ["a" * 40]})
        self.assertFalse(mechanical["requires_human"])
        self.assertIn("verified_commits", self.hub.dossier.current("system-a")["payload"])

    def test_restricted_material_is_never_accepted_or_projected(self):
        with self.assertRaises(PolicyDenied):
            self.hub.dossier.propose("system-a", {"test_evidence": ["SYNTHETIC PHI: forbidden"]})
        with self.assertRaises(PolicyDenied):
            self.hub.dossier.create_draft("system-a", {"purpose": "x", "password": "not-real"})
        projection = self.hub.dossier.safe_projection("system-a", ["purpose", "architecture", "missing"])
        self.assertEqual(projection["excluded"], ["missing"])
        self.assertNotIn("secret_identifiers", projection["facts"])


if __name__ == "__main__":
    unittest.main()

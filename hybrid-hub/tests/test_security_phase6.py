from __future__ import annotations

import base64
import json
import subprocess
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from hybrid_hub.errors import ConflictError, PolicyDenied, ValidationError
from hybrid_hub.hub import Hub
from hybrid_hub.secrets import SyntheticMemoryBackend, secret_variants


def git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "-c", "user.name=Hub Tests", "-c", "user.email=hub@example.invalid", "commit", "-qm", "synthetic baseline"], check=True)


class Phase6SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.hub = Hub(self.root / "runtime")
        self.workspace, self.task_id, self.repo_id = self._system("secure-system", "secure-client", ["standard"])

    def tearDown(self):
        self.temporary.cleanup()

    def _system(self, system_id: str, client_id: str, profiles: list[str]):
        project = self.root / system_id
        project.mkdir()
        (project / "app.py").write_text("def ready(): return True\n", encoding="utf-8")
        git_repo(project)
        registration = self.hub.registry.register_system(system_id, client_id, system_id, [str(project)], profiles)
        discovery = self.hub.registry.discover(system_id)
        version = self.hub.dossier.create_draft(system_id, {"purpose": "Synthetic Phase 6", "hierarchy": {"repositories": [discovery["repositories"][0]["repo_id"]]}, "provenance": [{"source": "synthetic-test"}]})
        self.hub.dossier.approve(system_id, version, "test-owner")
        self.hub.registry.approve_system(system_id, "test-owner")
        task_id = f"{system_id}-task"
        task = self.hub.tasks.create(system_id, "Synthetic secret and egress task", registration["policy"]["classification"], registration["policy"]["policy_hash"], task_id)
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            self.hub.tasks.transition(task_id, state)
        repo_id = discovery["repositories"][0]["repo_id"]
        manifest = self.hub.workspaces.create(task_id, [repo_id])
        self.hub.tasks.transition(task_id, "WORKSPACES_READY", evidence=[manifest["manifest_hash"]])
        return Path(manifest["repositories"][0]["workspace"]), task_id, repo_id

    def capability(self, command: str, *, system_id: str = "secure-system"):
        specification = {"name": "synthetic-check", "argv": ["$PYTHON", "-c", command], "secret_bindings": {"SYNTHETIC_API_TOKEN": "synthetic-token"}, "network_mode": "none", "environment": "local-synthetic"}
        proposal = self.hub.capabilities.propose(system_id, specification, "test-proposer")
        return proposal, specification

    def test_secret_capability_requires_approval_and_rejects_real_backend_values(self):
        proposal, _ = self.capability("print('ok')")
        backend = SyntheticMemoryBackend({"synthetic-token": "hh_test_CANARY_PHASE6_NOT_REAL"})
        with self.assertRaises(PolicyDenied):
            self.hub.secret_runner.run(self.task_id, proposal["capability_id"], backend)
        self.hub.capabilities.approve(proposal["capability_id"], "test-owner")
        result = self.hub.secret_runner.run(self.task_id, proposal["capability_id"], backend)
        self.assertTrue(result["passed"])
        with self.assertRaises(ValidationError):
            SyntheticMemoryBackend({"synthetic-token": "looks-like-a-real-secret"})

    def test_exact_and_encoded_secret_variants_never_enter_output_audit_or_database(self):
        canary = "hh_test_CANARY_PHASE6_ENCODED_NOT_REAL"
        variants = sorted(secret_variants(canary))
        command = "import os,base64,urllib.parse;v=os.environ['SYNTHETIC_API_TOKEN'];print(v);print(base64.b64encode(v.encode()).decode());print(v.encode().hex());print(urllib.parse.quote(v,safe=''))"
        proposal, _ = self.capability(command)
        self.hub.capabilities.approve(proposal["capability_id"], "test-owner")
        result = self.hub.secret_runner.run(self.task_id, proposal["capability_id"], SyntheticMemoryBackend({"synthetic-token": canary}))
        artifact = self.hub.database.layout.artifacts / result["evidence_digest"][:2] / result["evidence_digest"]
        evidence = artifact.read_text(encoding="utf-8")
        for variant in variants:
            self.assertNotIn(variant, evidence)
            self.assertNotIn(variant, json.dumps(self.hub.audit.export()))
            self.assertNotIn(variant.encode(), self.hub.database.layout.db.read_bytes())
        self.assertIn("[REDACTED_SECRET]", evidence)
        self.assertFalse(result["secret_values_exposed"])

    def test_secret_runner_has_no_network_and_cannot_cross_system_capability(self):
        proposal, _ = self.capability("import socket; socket.create_connection(('1.1.1.1',53),timeout=1)")
        self.hub.capabilities.approve(proposal["capability_id"], "test-owner")
        backend = SyntheticMemoryBackend({"synthetic-token": "hh_test_CANARY_NETWORK_NOT_REAL"})
        result = self.hub.secret_runner.run(self.task_id, proposal["capability_id"], backend)
        self.assertFalse(result["passed"])
        _, other_task, _ = self._system("other-secure", "other-client", ["standard"])
        with self.assertRaises(PolicyDenied):
            self.hub.secret_runner.run(other_task, proposal["capability_id"], backend)

    def test_capability_cannot_request_network_or_non_synthetic_environment(self):
        base = {"name": "bad", "argv": ["$PYTHON", "-c", "print('x')"], "secret_bindings": {"TOKEN": "synthetic-token"}}
        with self.assertRaises(PolicyDenied):
            self.hub.capabilities.propose("secure-system", {**base, "network_mode": "public"}, "test-proposer")
        with self.assertRaises(PolicyDenied):
            self.hub.capabilities.propose("secure-system", {**base, "environment": "production"}, "test-proposer")

    def test_egress_redacts_known_secret_and_seals_human_approved_bundle(self):
        canary = "hh_test_CANARY_EGRESS_NOT_REAL"
        encoded = base64.b64encode(canary.encode()).decode()
        (self.workspace / "safe.py").write_text(f"API_KEY={canary}\nENCODED={encoded}\ndef result(): return 'safe'\n", encoding="utf-8")
        manifest = self.hub.egress.build(self.task_id, "codex-cloud", [{"repo_id": self.repo_id, "path": "safe.py"}], known_secret_values=[canary])
        self.assertFalse(manifest["transmission_enabled"])
        self.assertFalse(manifest["managed_policy_allows_transmission"])
        self.assertTrue(manifest["files"][0]["redacted"])
        bundle = self.hub.egress.approve(manifest["bundle_id"], "test-owner")
        self.assertEqual(bundle["status"], "approved")
        egress_file = self.hub.database.layout.egress / self.task_id / manifest["bundle_id"] / "files" / self.repo_id / "safe.py"
        content = egress_file.read_text(encoding="utf-8")
        self.assertNotIn(canary, content)
        self.assertNotIn(encoded, content)
        self.assertIn("[REDACTED_SECRET]", content)
        self.assertNotIn(canary, json.dumps(self.hub.audit.export()))

    def test_unknown_credentials_phi_pii_and_privileged_text_block_egress(self):
        cases = {
            "credential.py": "password=unknowncredentialvalue\n",
            "phi.txt": "patient medical record name: Example\n",
            "pii.txt": "SSN: 000-00-0000\n",
            "legal.txt": "ATTORNEY-CLIENT PRIVILEGED work product\n",
        }
        for filename, content in cases.items():
            (self.workspace / filename).write_text(content, encoding="utf-8")
            with self.subTest(filename=filename), self.assertRaises(PolicyDenied):
                self.hub.egress.build(self.task_id, "claude-cloud", [{"repo_id": self.repo_id, "path": filename}])

    def test_archives_binaries_logs_databases_symlinks_and_bidi_are_rejected(self):
        (self.workspace / "archive.zip").write_bytes(b"PK\x03\x04")
        (self.workspace / "binary.bin").write_bytes(b"abc\x00def")
        (self.workspace / "trace.log").write_text("safe-looking log", encoding="utf-8")
        (self.workspace / "data.sqlite").write_bytes(b"SQLite format 3\x00")
        (self.workspace / "bidi.txt").write_text("safe\u202esecret", encoding="utf-8")
        (self.workspace / "link.txt").symlink_to(self.workspace / "app.py")
        for filename in ("archive.zip", "binary.bin", "trace.log", "data.sqlite", "bidi.txt", "link.txt"):
            with self.subTest(filename=filename), self.assertRaises(PolicyDenied):
                self.hub.egress.build(self.task_id, "codex-cloud", [{"repo_id": self.repo_id, "path": filename}])

    def test_bundle_tampering_blocks_approval(self):
        (self.workspace / "safe.txt").write_text("public synthetic source", encoding="utf-8")
        manifest = self.hub.egress.build(self.task_id, "codex-cloud", [{"repo_id": self.repo_id, "path": "safe.txt"}])
        egress_file = self.hub.database.layout.egress / self.task_id / manifest["bundle_id"] / "files" / self.repo_id / "safe.txt"
        egress_file.chmod(0o600)
        egress_file.write_text("tampered", encoding="utf-8")
        with self.assertRaises(PolicyDenied):
            self.hub.egress.approve(manifest["bundle_id"], "test-owner")

    def test_confidential_policy_and_cross_task_repository_block_egress(self):
        confidential_workspace, confidential_task, confidential_repo = self._system("confidential-system", "confidential-client", ["confidential"])
        (confidential_workspace / "safe.txt").write_text("safe", encoding="utf-8")
        with self.assertRaises(PolicyDenied):
            self.hub.egress.build(confidential_task, "codex-cloud", [{"repo_id": confidential_repo, "path": "safe.txt"}])
        (self.workspace / "safe.txt").write_text("safe", encoding="utf-8")
        with self.assertRaises(PolicyDenied):
            self.hub.egress.build(self.task_id, "codex-cloud", [{"repo_id": confidential_repo, "path": "safe.txt"}])


if __name__ == "__main__":
    unittest.main()

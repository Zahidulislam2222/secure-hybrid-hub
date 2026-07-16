from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from hybrid_hub.hub import Hub


def commit(path: Path, message: str = "synthetic baseline") -> str:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "-c", "user.name=Hub Tests", "-c", "user.email=hub@example.invalid", "commit", "-qm", message], check=True)
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


class QualityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.hub = Hub(self.root / "runtime")

    def tearDown(self):
        self.temporary.cleanup()

    def project(self, *, system_id: str = "quality-system", profiles: list[str] | None = None, topology: dict | None = None):
        project = self.root / system_id
        project.mkdir()
        if topology:
            (project / "hub-topology.json").write_text(json.dumps(topology), encoding="utf-8")
            for component in topology["components"]:
                component_root = project / component["path"]
                component_root.mkdir(parents=True, exist_ok=True)
                (component_root / "service.py").write_text("def ready():\n    return True\n", encoding="utf-8")
        else:
            (project / "app.py").write_text("def ready():\n    return True\n", encoding="utf-8")
            tests = project / "tests"
            tests.mkdir()
            (tests / "test_app.py").write_text("import unittest\nfrom app import ready\n\nclass AppTests(unittest.TestCase):\n    def test_ready(self):\n        self.assertTrue(ready())\n", encoding="utf-8")
        commit(project)
        registration = self.hub.registry.register_system(system_id, f"{system_id}-client", system_id, [str(project)], profiles or ["standard"])
        discovery = self.hub.registry.discover(system_id)
        version = self.hub.dossier.create_draft(system_id, {"purpose": "Synthetic quality verification", "hierarchy": {"repositories": [item["repo_id"] for item in discovery["repositories"]]}, "provenance": [{"source": "synthetic-test"}]})
        self.hub.dossier.approve(system_id, version, "test-owner")
        self.hub.registry.approve_system(system_id, "test-owner")
        task = self.hub.tasks.create(system_id, "Synthetic implementation", registration["policy"]["classification"], registration["policy"]["policy_hash"], f"{system_id}-task")
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            self.hub.tasks.transition(task["task_id"], state)
        repo_id = discovery["repositories"][0]["repo_id"]
        manifest = self.hub.workspaces.create(task["task_id"], [repo_id])
        self.hub.tasks.transition(task["task_id"], "WORKSPACES_READY", evidence=[manifest["manifest_hash"]])
        self.hub.tasks.transition(task["task_id"], "LOCAL_IMPLEMENTING")
        return project, Path(manifest["repositories"][0]["workspace"]), task["task_id"], repo_id

    def approve_commands(self, system_id: str, commands: list[dict]) -> str:
        proposal = self.hub.quality_registry.propose(system_id, commands, "test-proposer")
        self.assertEqual(self.hub.quality_registry.active(system_id), [])
        approved = self.hub.quality_registry.approve(proposal["command_set_id"], "test-owner")
        self.assertEqual(approved["status"], "approved")
        return proposal["command_set_id"]

    def test_python_quality_passes_with_hashed_evidence_and_checkpoint(self):
        _, workspace, task_id, _ = self.project()
        (workspace / "app.py").write_text("def ready():\n    return 1 + 1 == 2\n", encoding="utf-8")
        summary = self.hub.quality.run(task_id, "targeted")
        self.assertTrue(summary["passed"], summary)
        self.assertEqual(summary["missing_gates"], [])
        self.assertEqual(len(summary["evidence_digest"]), 64)
        self.assertTrue(self.hub.audit.verify())
        latest = self.hub.quality.latest(task_id, "targeted")
        self.assertEqual(latest["run_id"], summary["run_id"])
        with self.hub.database.connect() as connection:
            checkpoints = connection.execute("SELECT COUNT(*) FROM checkpoints WHERE task_id=? AND phase=?", (task_id, f"quality-{summary['run_id']}")).fetchone()[0]
        self.assertEqual(checkpoints, 1)

    def test_broken_logic_fails_unit_gate(self):
        _, workspace, task_id, _ = self.project(system_id="broken-system")
        (workspace / "app.py").write_text("def ready():\n    return False\n", encoding="utf-8")
        summary = self.hub.quality.run(task_id, "targeted")
        self.assertFalse(summary["passed"])
        unit = next(item for item in summary["gates"] if item["gate"] == "unit")
        self.assertNotEqual(unit["exit_code"], 0)
        self.assertIsNotNone(unit["evidence_digest"])

    def test_deleted_assertion_blocks_commands_before_execution(self):
        _, workspace, task_id, _ = self.project(system_id="weak-test-system")
        (workspace / "tests" / "test_app.py").write_text("import unittest\n\nclass AppTests(unittest.TestCase):\n    def test_ready(self):\n        pass\n", encoding="utf-8")
        summary = self.hub.quality.run(task_id, "targeted")
        self.assertFalse(summary["passed"])
        integrity = next(item for item in summary["gates"] if item["gate"] == "test-integrity")
        self.assertTrue(any("removed test assertions" in finding for finding in integrity["findings"]))
        unit = next(item for item in summary["gates"] if item["gate"] == "unit")
        self.assertIsNone(unit["exit_code"])
        self.assertIn("pre-execution safety gate", unit["findings"][0])

    def test_secret_canary_fails_without_entering_evidence_or_audit(self):
        canary = "hh_test_CANARY_ABC123_NOT_REAL"
        _, workspace, task_id, _ = self.project(system_id="secret-system")
        (workspace / ".env").write_text(f"API_KEY={canary}\n", encoding="utf-8")
        summary = self.hub.quality.run(task_id, "targeted")
        self.assertFalse(summary["passed"])
        self.assertNotIn(canary, json.dumps(summary))
        self.assertNotIn(canary, json.dumps(self.hub.audit.export()))
        artifact = self.hub.database.layout.artifacts / summary["evidence_digest"][:2] / summary["evidence_digest"]
        self.assertNotIn(canary, artifact.read_text(encoding="utf-8"))

    def test_breaking_contract_and_destructive_migration_are_detected(self):
        project, workspace, task_id, _ = self.project(system_id="contract-system")
        schema = project / "event.schema.json"
        schema.write_text(json.dumps({"type": "object", "properties": {"id": {"type": "string"}, "status": {"type": "string"}}, "required": ["id"]}), encoding="utf-8")
        migrations = project / "migrations"
        migrations.mkdir()
        (migrations / "001.sql").write_text("CREATE TABLE cases(id TEXT);", encoding="utf-8")
        commit(project, "add contract baseline")
        # Workspaces freeze the original base, so use a fresh system for the baseline.
        self.temporary.cleanup()
        self.setUp()
        project, workspace, task_id, _ = self._contract_project()
        (workspace / "event.schema.json").write_text(json.dumps({"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id", "new_required"]}), encoding="utf-8")
        (workspace / "migrations" / "001.sql").write_text("DROP TABLE cases;", encoding="utf-8")
        summary = self.hub.quality.run(task_id, "targeted")
        contract = next(item for item in summary["gates"] if item["gate"] == "contract-compatibility")
        self.assertFalse(contract["passed"])
        self.assertTrue(any("removed properties" in finding for finding in contract["findings"]))
        self.assertTrue(any("destructive migration" in finding for finding in contract["findings"]))

    def _contract_project(self):
        project = self.root / "contract-system"
        project.mkdir()
        (project / "app.py").write_text("def ready(): return True\n", encoding="utf-8")
        tests = project / "tests"
        tests.mkdir()
        (tests / "test_app.py").write_text("import unittest\nclass T(unittest.TestCase):\n def test_ok(self): self.assertTrue(True)\n", encoding="utf-8")
        (project / "event.schema.json").write_text(json.dumps({"type": "object", "properties": {"id": {"type": "string"}, "status": {"type": "string"}}, "required": ["id"]}), encoding="utf-8")
        migrations = project / "migrations"
        migrations.mkdir()
        (migrations / "001.sql").write_text("CREATE TABLE cases(id TEXT);", encoding="utf-8")
        commit(project)
        registration = self.hub.registry.register_system("contract-system", "contract-client", "Contract", [str(project)], ["standard"])
        discovery = self.hub.registry.discover("contract-system")
        version = self.hub.dossier.create_draft("contract-system", {"purpose": "Contract test", "hierarchy": {"repositories": [discovery["repositories"][0]["repo_id"]]}, "provenance": [{"source": "synthetic-test"}]})
        self.hub.dossier.approve("contract-system", version, "test-owner")
        self.hub.registry.approve_system("contract-system", "test-owner")
        task = self.hub.tasks.create("contract-system", "Change contract", "R1", registration["policy"]["policy_hash"], "contract-task")
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            self.hub.tasks.transition("contract-task", state)
        manifest = self.hub.workspaces.create("contract-task", [discovery["repositories"][0]["repo_id"]])
        self.hub.tasks.transition("contract-task", "WORKSPACES_READY", evidence=[manifest["manifest_hash"]])
        self.hub.tasks.transition("contract-task", "LOCAL_IMPLEMENTING")
        return project, Path(manifest["repositories"][0]["workspace"]), "contract-task", discovery["repositories"][0]["repo_id"]

    def test_landlock_denies_reading_files_outside_disposable_snapshot(self):
        outside = self.root / "outside.txt"
        outside.write_text("must-not-be-readable", encoding="utf-8")
        _, _, task_id, repo_id = self.project(system_id="landlock-system")
        self.approve_commands("landlock-system", [{"command_id": "isolation-check", "gate": "unit", "repository_id": repo_id, "argv": ["$PYTHON", "-c", f"from pathlib import Path; Path({str(outside)!r}).read_text()"]}])
        summary = self.hub.quality.run(task_id, "targeted")
        self.assertFalse(summary["passed"])
        gate = next(item for item in summary["gates"] if item["command_id"] == "isolation-check")
        self.assertNotEqual(gate["exit_code"], 0)
        evidence = self.hub.database.layout.artifacts / gate["evidence_digest"][:2] / gate["evidence_digest"]
        self.assertNotIn("must-not-be-readable", evidence.read_text(encoding="utf-8"))

    def test_network_namespace_denies_socket_access(self):
        _, _, task_id, repo_id = self.project(system_id="network-system")
        self.approve_commands("network-system", [{"command_id": "network-check", "gate": "unit", "repository_id": repo_id, "argv": ["$PYTHON", "-c", "import socket; socket.create_connection(('1.1.1.1', 53), timeout=1)"]}])
        summary = self.hub.quality.run(task_id, "targeted")
        self.assertFalse(summary["passed"])
        gate = next(item for item in summary["gates"] if item["command_id"] == "network-check")
        self.assertNotEqual(gate["exit_code"], 0)

    def test_command_receives_clean_environment_and_mutates_only_snapshot(self):
        _, workspace, task_id, repo_id = self.project(system_id="snapshot-system")
        original = (workspace / "app.py").read_text(encoding="utf-8")
        self.approve_commands("snapshot-system", [{"command_id": "snapshot-unit", "gate": "unit", "repository_id": repo_id, "argv": ["$PYTHON", "-c", "import os,pathlib; assert 'OPENAI_API_KEY' not in os.environ; pathlib.Path('app.py').write_text('mutated in snapshot')"]}])
        previous = os.environ.get("OPENAI_API_KEY")
        os.environ["OPENAI_API_KEY"] = "synthetic-parent-value"
        try:
            summary = self.hub.quality.run(task_id, "targeted")
        finally:
            if previous is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = previous
        self.assertTrue(summary["passed"], summary)
        self.assertEqual((workspace / "app.py").read_text(encoding="utf-8"), original)

    def test_regulated_profile_missing_specialized_gates_fails_closed(self):
        _, _, task_id, _ = self.project(system_id="health-system", profiles=["healthcare"])
        summary = self.hub.quality.run(task_id, "targeted")
        self.assertFalse(summary["passed"])
        self.assertIn("audit-completeness", summary["missing_gates"])
        self.assertIn("privacy-retention", summary["missing_gates"])
        self.assertNotIn("phi-scan", summary["missing_gates"])

    def test_targeted_monorepo_runs_only_affected_component_commands(self):
        topology = {"components": [{"id": "alpha", "path": "packages/alpha", "type": "service"}, {"id": "beta", "path": "packages/beta", "type": "service"}], "dependencies": []}
        _, workspace, task_id, repo_id = self.project(system_id="mono-system", topology=topology)
        self.approve_commands("mono-system", [
            {"command_id": "alpha-unit", "gate": "unit", "repository_id": repo_id, "component": "alpha", "argv": ["$PYTHON", "-c", "raise SystemExit(0)"]},
            {"command_id": "beta-extra", "gate": "beta-check", "repository_id": repo_id, "component": "beta", "argv": ["$PYTHON", "-c", "raise SystemExit(0)"]},
        ])
        (workspace / "packages" / "alpha" / "service.py").write_text("def ready():\n    return 2 + 2 == 4\n", encoding="utf-8")
        summary = self.hub.quality.run(task_id, "targeted")
        self.assertTrue(summary["passed"], summary)
        command_ids = {item["command_id"] for item in summary["gates"]}
        self.assertIn("alpha-unit", command_ids)
        self.assertNotIn("beta-extra", command_ids)
        self.assertEqual(summary["affected_components"][repo_id], ["alpha"])

    def test_polyrepo_microservice_contract_integration_runs_in_combined_snapshot(self):
        fixture = Path(__file__).resolve().parent / "fixtures" / "polyrepo"
        roots = []
        for name in ("contracts", "appointment-service", "notification-service"):
            destination = self.root / name
            shutil.copytree(fixture / name, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            commit(destination)
            roots.append(str(destination))
        registration = self.hub.registry.register_system("poly-quality", "poly-client", "Poly Quality", roots, ["standard"])
        discovery = self.hub.registry.discover("poly-quality")
        version = self.hub.dossier.create_draft("poly-quality", {"purpose": "Synthetic polyrepo integration", "hierarchy": {"repositories": [item["repo_id"] for item in discovery["repositories"]]}, "provenance": [{"source": "synthetic-test"}]})
        self.hub.dossier.approve("poly-quality", version, "test-owner")
        self.hub.registry.approve_system("poly-quality", "test-owner")
        by_name = {Path(item["path"]).name: item["repo_id"] for item in discovery["repositories"]}
        integration = (
            "import importlib.util,json,pathlib;"
            f"root=pathlib.Path('.');contract=json.loads((root/'{by_name['contracts']}'/'cancellation.schema.json').read_text());"
            "assert set(contract['required'])=={'appointment_id','status'};"
            f"a=importlib.util.spec_from_file_location('a',root/'{by_name['appointment-service']}'/'service.py');am=importlib.util.module_from_spec(a);a.loader.exec_module(am);"
            f"n=importlib.util.spec_from_file_location('n',root/'{by_name['notification-service']}'/'service.py');nm=importlib.util.module_from_spec(n);n.loader.exec_module(nm);"
            "event=am.emit_cancellation('synthetic-1');assert nm.consume_cancellation(event)"
        )
        self.approve_commands("poly-quality", [
            {"command_id": "poly-parse", "gate": "parse", "workspace_scope": "system", "argv": ["$PYTHON", "-c", "import pathlib; assert len(list(pathlib.Path('.').glob('*/service.py'))) == 2"]},
            {"command_id": "poly-integration", "gate": "unit", "workspace_scope": "system", "argv": ["$PYTHON", "-c", integration]},
        ])
        task = self.hub.tasks.create("poly-quality", "Verify cancellation contract", "R1", registration["policy"]["policy_hash"], "poly-quality-task")
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            self.hub.tasks.transition(task["task_id"], state)
        manifest = self.hub.workspaces.create(task["task_id"], [item["repo_id"] for item in discovery["repositories"]])
        self.hub.tasks.transition(task["task_id"], "WORKSPACES_READY", evidence=[manifest["manifest_hash"]])
        self.hub.tasks.transition(task["task_id"], "LOCAL_IMPLEMENTING")
        summary = self.hub.quality.run(task["task_id"], "targeted")
        self.assertTrue(summary["passed"], summary)
        integration_gate = next(item for item in summary["gates"] if item["command_id"] == "poly-integration")
        self.assertEqual(set(integration_gate["covered_repositories"]), set(by_name.values()))
        self.assertEqual(summary["missing_gates"], [])


if __name__ == "__main__":
    unittest.main()

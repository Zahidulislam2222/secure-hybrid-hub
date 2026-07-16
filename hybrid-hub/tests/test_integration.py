from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hybrid_hub.errors import ConflictError, PolicyDenied
from hybrid_hub.hub import Hub
from hybrid_hub.policy import compose
from hybrid_hub.topology import Topology
from hybrid_hub.workers import LocalAdapterConfig, LocalWorker

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def git_repo(path: Path) -> str:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "-c", "user.name=Hub Tests", "-c", "user.email=hub@example.invalid", "commit", "-qm", "synthetic baseline"], check=True)
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


class IntegrationBase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.hub = Hub(self.root / "runtime")

    def tearDown(self):
        self.temporary.cleanup()

    def register(self, system_id="system-a", client_id="client-a", fixture="single_repo", profiles=None, git=False):
        project = self.root / f"{system_id}-project"
        shutil.copytree(FIXTURES / fixture, project)
        if git:
            git_repo(project)
        registration = self.hub.registry.register_system(system_id, client_id, system_id, [str(project)], profiles or ["confidential"])
        self.hub.registry.discover(system_id)
        version = self.hub.dossier.create_draft(system_id, {"purpose": "Synthetic integration", "hierarchy": {"repositories": registration["roots"]}, "provenance": [{"source": "fixture"}], "architecture": {"status": "approved synthetic"}})
        self.hub.dossier.approve(system_id, version, "test-owner")
        self.hub.registry.approve_system(system_id, "test-owner")
        return project, registration


class RegistryTopologyTests(IntegrationBase):
    def test_single_and_monorepo_discovery(self):
        _, _ = self.register(fixture="monorepo")
        report = self.hub.registry.discover("system-a")
        ids = {item["id"] for item in report["repositories"][0]["components"]}
        self.assertEqual(ids, {"appointments", "notifications"})
        self.assertFalse(report["content_sent_to_cloud"])

    def test_cross_client_root_reuse_is_denied(self):
        project, _ = self.register()
        with self.assertRaises(ConflictError):
            self.hub.registry.register_system("system-b", "client-b", "Other", [str(project)], [])

    def test_approval_requires_discovery_and_approved_dossier(self):
        project = self.root / "undiscovered"
        project.mkdir()
        self.hub.registry.register_system("undiscovered", "client-u", "Undiscovered", [str(project)], [])
        with self.assertRaises(Exception):
            self.hub.registry.approve_system("undiscovered", "owner-u")

    def test_polyrepo_affected_graph_and_release_manifest(self):
        definition = json.loads((FIXTURES / "polyrepo" / "system.json").read_text())
        components = [{"id": name} for name in definition["components"]]
        topology = Topology(components, definition["dependencies"])
        self.assertEqual(set(topology.affected({"contracts"})), set(definition["components"]))
        revisions = {name: str(index) * 40 for index, name in enumerate(definition["components"], 1)}
        manifest = topology.release_manifest(revisions, definition["deployment_order"])
        self.assertEqual(manifest["rollback_order"], list(reversed(definition["deployment_order"])))
        self.assertEqual(len(manifest["manifest_hash"]), 64)


class TaskCheckpointTests(IntegrationBase):
    def test_state_checkpoint_is_atomic_and_idempotent(self):
        _, registration = self.register()
        task = self.hub.tasks.create("system-a", "Synthetic task", "R1", registration["policy"]["policy_hash"], "task-atomic")
        with self.assertRaises(OSError):
            self.hub.tasks.transition("task-atomic", "REGISTERED_CONTEXT", fail_checkpoint=True)
        self.assertEqual(self.hub.tasks.get("task-atomic")["state"], "NEW")
        transitioned = self.hub.tasks.transition("task-atomic", "REGISTERED_CONTEXT")
        again = self.hub.tasks.transition("task-atomic", "REGISTERED_CONTEXT")
        self.assertEqual(transitioned["state"], again["state"])
        with self.hub.database.connect() as connection:
            count = connection.execute("SELECT COUNT(*) FROM checkpoints WHERE task_id=? AND state='REGISTERED_CONTEXT'", ("task-atomic",)).fetchone()[0]
        self.assertEqual(count, 1)
        self.assertTrue(self.hub.audit.verify())

    def test_cancel_blocks_local_worker(self):
        _, registration = self.register()
        task = self.hub.tasks.create("system-a", "Synthetic", "R1", registration["policy"]["policy_hash"], "task-cancel")
        self.hub.tasks.cancel(task["task_id"])
        worker = LocalWorker(self.hub.database, self.hub.audit, self.hub.leases, LocalAdapterConfig("codex-local", "http://127.0.0.1:11434", "qwen3:1.7b"))
        with self.assertRaises(PolicyDenied):
            worker.run_structured(task["task_id"], '{"status":"ok"}')

    def test_disabled_system_is_opted_out_for_new_tasks(self):
        _, registration = self.register()
        self.hub.registry.disable_system("system-a", "test-owner")
        with self.assertRaises(PolicyDenied):
            self.hub.tasks.create("system-a", "Should not start", "R1", registration["policy"]["policy_hash"], "task-disabled")


class WorkspaceTests(IntegrationBase):
    def test_one_writer_and_git_worktree(self):
        project, registration = self.register(git=True)
        report = self.hub.registry.discover("system-a")
        repo_id = report["repositories"][0]["repo_id"]
        task = self.hub.tasks.create("system-a", "Synthetic workspace", "R1", registration["policy"]["policy_hash"], "task-worktree")
        manifest = self.hub.workspaces.create(task["task_id"], [repo_id])
        workspace = Path(manifest["repositories"][0]["workspace"])
        self.assertTrue((workspace / ".git").exists())
        self.assertEqual(manifest["repositories"][0]["base_commit"], subprocess.check_output(["git", "-C", str(project), "rev-parse", "HEAD"], text=True).strip())
        with self.assertRaises(ConflictError):
            self.hub.leases.acquire(f"repo:{repo_id}", "other-task")
        self.assertEqual(self.hub.workspaces.create(task["task_id"], [repo_id])["manifest_hash"], manifest["manifest_hash"])

    def test_polyrepo_cross_repository_workspace(self):
        roots = []
        for name in ("contracts", "appointment-service", "notification-service"):
            destination = self.root / name
            shutil.copytree(FIXTURES / "polyrepo" / name, destination)
            git_repo(destination)
            roots.append(str(destination))
        registration = self.hub.registry.register_system("poly-system", "poly-client", "Poly", roots, ["confidential"])
        report = self.hub.registry.discover("poly-system")
        version = self.hub.dossier.create_draft("poly-system", {"purpose": "Synthetic polyrepo", "hierarchy": {"repositories": [item["repo_id"] for item in report["repositories"]]}, "provenance": [{"source": "fixture"}]})
        self.hub.dossier.approve("poly-system", version, "poly-owner")
        self.hub.registry.approve_system("poly-system", "poly-owner")
        task = self.hub.tasks.create("poly-system", "Cross-service synthetic change", "R1", registration["policy"]["policy_hash"], "task-poly")
        manifest = self.hub.workspaces.create(task["task_id"], [item["repo_id"] for item in report["repositories"]])
        self.assertEqual(len(manifest["repositories"]), 3)
        self.assertEqual(len({item["repo_id"] for item in manifest["repositories"]}), 3)


class LocalWorkerTests(IntegrationBase):
    def setUp(self):
        super().setUp()
        _, registration = self.register()
        self.task = self.hub.tasks.create("system-a", "Synthetic worker", "R1", registration["policy"]["policy_hash"], "task-worker")
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED", "WORKSPACES_READY"):
            self.hub.tasks.transition(self.task["task_id"], state)

    def test_codex_and_claude_local_structured_exchange(self):
        codex = LocalWorker(self.hub.database, self.hub.audit, self.hub.leases, LocalAdapterConfig("codex-local", "http://127.0.0.1:11434", "qwen3:1.7b"))
        with patch.object(codex, "_request", return_value={"response": '{"status":"ok","changed_paths":[]}'}) as request:
            result = codex.run_structured(self.task["task_id"], "Return a JSON object with status and changed_paths.")
        self.assertEqual(result["result"]["status"], "ok")
        self.assertEqual(request.call_args.args[1], "/api/generate")
        claude = LocalWorker(self.hub.database, self.hub.audit, self.hub.leases, LocalAdapterConfig("claude-local", "http://localhost:11434", "gemma3:1b"))
        with patch.object(claude, "_request", return_value={"content": [{"type": "text", "text": '{"status":"ok","changed_paths":[]}'}]}) as request:
            result = claude.run_structured(self.task["task_id"], "Return JSON status.")
        self.assertEqual(result["result"], {"status": "ok", "changed_paths": []})
        self.assertEqual(request.call_args.args[1], "/v1/messages")

    def test_terminal_framing_selects_last_valid_json_object(self):
        framed = '\x1b[?25lThinking about {"draft":true}\x1b[?25h done.\n{"status":"ok","changed_paths":[]}'
        self.assertEqual(LocalWorker._parse_json(framed), {"status": "ok", "changed_paths": []})

    def test_incomplete_model_contract_is_rejected(self):
        with self.assertRaises(Exception):
            LocalWorker._validate_result({"status": "ok"})

    def test_worker_rejects_secret_context_and_nonloopback(self):
        worker = LocalWorker(self.hub.database, self.hub.audit, self.hub.leases, LocalAdapterConfig("codex-local", "http://127.0.0.1:11434", "qwen3:1.7b"))
        with self.assertRaises(PolicyDenied):
            worker.run_structured(self.task["task_id"], "token=hh_test_CANARY_X_NOT_REAL")
        with self.assertRaises(PolicyDenied):
            LocalAdapterConfig("codex-local", "http://8.8.8.8:11434", "qwen3:1.7b")

    def test_bounded_executable_transport(self):
        with patch("pathlib.Path.is_file", return_value=True), patch("subprocess.run") as process:
            worker = LocalWorker(self.hub.database, self.hub.audit, self.hub.leases, LocalAdapterConfig("codex-local", "http://127.0.0.1:11434", "qwen3:1.7b", executable="/bin/ollama"))
            process.return_value.returncode = 0
            process.return_value.stdout = "NAME ID SIZE MODIFIED\nqwen3:1.7b abc 1GB now\n"
            process.return_value.stderr = ""
            report = worker.preflight()
        self.assertEqual(report["transport"], "bounded-ollama-cli")
        passed_env = process.call_args.kwargs["env"]
        self.assertNotIn("OPENAI_API_KEY", passed_env)
        self.assertEqual(passed_env["OLLAMA_NO_CLOUD"], "1")

    def test_executable_transport_enforces_json_and_disables_word_wrap(self):
        with patch("pathlib.Path.is_file", return_value=True), patch("subprocess.run") as process:
            worker = LocalWorker(self.hub.database, self.hub.audit, self.hub.leases, LocalAdapterConfig("codex-local", "http://127.0.0.1:11434", "gemma3:1b", executable="/bin/ollama"))
            process.return_value.returncode = 0
            process.return_value.stdout = '{"status":"ok","changed_paths":[]}'
            process.return_value.stderr = ""
            worker.run_structured(self.task["task_id"], "Return the required object.")
        argv = process.call_args.args[0]
        self.assertIn("--format", argv)
        self.assertIn("json", argv)
        self.assertIn("--nowordwrap", argv)
        self.assertIn("--hidethinking", argv)

    def test_file_worker_uses_bounded_raw_content_and_broker_stop_sequence(self):
        with patch("pathlib.Path.is_file", return_value=True), patch.object(LocalWorker, "_bridge_request", return_value={"response": "```python\ndef ready():\n    return True\n```\n<<END_FILE>>", "done": True, "done_reason": "stop"}) as bridge:
            worker = LocalWorker(self.hub.database, self.hub.audit, self.hub.leases, LocalAdapterConfig("codex-local", "http://127.0.0.1:11434", "gemma3:1b", http_bridge_executable="/bin/curl"))
            result = worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertEqual(result["result"]["content"], "def ready():\n    return True\n")
        payload = bridge.call_args.args[2]
        self.assertEqual(payload["options"]["num_predict"], 2048)
        self.assertEqual(payload["options"]["stop"], ["<<END_FILE>>"])

    def test_file_worker_rejects_output_limit_and_cli_transport(self):
        with patch("pathlib.Path.is_file", return_value=True), patch.object(LocalWorker, "_bridge_request", return_value={"response": "partial", "done": False}):
            worker = LocalWorker(self.hub.database, self.hub.audit, self.hub.leases, LocalAdapterConfig("codex-local", "http://127.0.0.1:11434", "gemma3:1b", http_bridge_executable="/bin/curl"))
            with self.assertRaises(Exception):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        with patch("pathlib.Path.is_file", return_value=True):
            cli_worker = LocalWorker(self.hub.database, self.hub.audit, self.hub.leases, LocalAdapterConfig("codex-local", "http://127.0.0.1:11434", "gemma3:1b", executable="/bin/ollama"))
            with self.assertRaises(Exception):
                cli_worker.run_file(self.task["task_id"], "Generate one synthetic file.")


class CLIAcceptanceTests(IntegrationBase):
    def invoke(self, *arguments, expected=0):
        result = subprocess.run(["python3", str(ROOT / "hub.py"), "--runtime", str(self.root / "cli-runtime"), *arguments], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_one_command_local_only_flow_and_blocked_later_phase(self):
        project = self.root / "cli-project"
        shutil.copytree(FIXTURES / "single_repo", project)
        initialized = self.invoke("system", "init", "--id", "cli-system", "--client", "cli-client", "--name", "CLI Synthetic", "--root", str(project), "--profile", "confidential", "--purpose", "Synthetic CLI acceptance")
        self.assertFalse(initialized["result"]["approved"])
        self.invoke("system", "approve", "cli-system", "--approver", "cli-owner")
        run = self.invoke("run", "Add synthetic cancellation", "--system", "cli-system", "--task-id", "task-cli")
        self.assertEqual(run["result"]["task"]["state"], "WORKSPACES_READY")
        status = self.invoke("status", "task-cli")
        self.assertEqual(status["result"]["state"], "WORKSPACES_READY")
        blocked = self.invoke("research", "fetch", "task-cli", "--url", "https://docs.python.org/3/", expected=2)
        self.assertEqual(blocked["error"], "PolicyDenied")

    def test_task_classification_cannot_be_lowered_below_system(self):
        project = self.root / "classified-project"
        shutil.copytree(FIXTURES / "single_repo", project)
        self.invoke("system", "init", "--id", "health-system", "--client", "health-client", "--name", "Health Synthetic", "--root", str(project), "--profile", "healthcare", "--purpose", "Synthetic classification")
        self.invoke("system", "approve", "health-system", "--approver", "health-owner")
        run = self.invoke("run", "Synthetic low label", "--system", "health-system", "--classification", "R0", "--task-id", "task-classified", "--through", "scoped")
        self.assertEqual(run["result"]["classification"], "R2")

    def test_cli_quality_runs_targeted_then_full_with_deterministic_evidence(self):
        project = self.root / "quality-cli-project"
        project.mkdir()
        (project / "app.py").write_text("def ready():\n    return True\n", encoding="utf-8")
        tests = project / "tests"
        tests.mkdir()
        (tests / "test_app.py").write_text("import unittest\nfrom app import ready\nclass T(unittest.TestCase):\n def test_ready(self): self.assertTrue(ready())\n", encoding="utf-8")
        git_repo(project)
        initialized = self.invoke("system", "init", "--id", "quality-cli", "--client", "quality-client", "--name", "Quality CLI", "--root", str(project), "--profile", "standard", "--purpose", "Synthetic quality CLI")
        repo_id = initialized["result"]["discovery"]["repositories"][0]["repo_id"]
        self.invoke("system", "approve", "quality-cli", "--approver", "quality-owner")
        run = self.invoke("run", "Change ready logic", "--system", "quality-cli", "--task-id", "task-quality-cli", "--create-workspaces", "--repo", repo_id)
        workspace = Path(run["result"]["workspace"]["repositories"][0]["workspace"])
        (workspace / "app.py").write_text("def ready():\n    return 3 * 3 == 9\n", encoding="utf-8")
        targeted = self.invoke("test", "task-quality-cli", "--scope", "targeted")
        self.assertTrue(targeted["result"]["passed"], targeted)
        self.assertEqual(self.invoke("status", "task-quality-cli")["result"]["state"], "TARGETED_TESTING")
        full = self.invoke("test", "task-quality-cli", "--scope", "full")
        self.assertTrue(full["result"]["passed"], full)
        self.assertEqual(self.invoke("status", "task-quality-cli")["result"]["state"], "FULL_QUALITY_GATES")


if __name__ == "__main__":
    unittest.main()

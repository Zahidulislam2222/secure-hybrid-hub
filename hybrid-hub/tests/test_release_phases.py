from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from hybrid_hub.cloud import ProviderProfile
from hybrid_hub.errors import AuthorizationRequired, PolicyDenied, ValidationError
from hybrid_hub.hub import Hub
from hybrid_hub.util import sha256_bytes


def git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "-c", "user.name=Hub Tests", "-c", "user.email=hub@example.invalid", "commit", "-qm", "synthetic baseline"], check=True)


class ReleaseBase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.hub = Hub(self.root / "runtime")

    def tearDown(self):
        self.temporary.cleanup()

    def task(self, suffix: str, *, profiles=None):
        project = self.root / f"project-{suffix}"
        project.mkdir()
        (project / "README.md").write_text("# Synthetic Calculator\n", encoding="utf-8")
        git_repo(project)
        system_id = f"system-{suffix}"
        registration = self.hub.registry.register_system(system_id, f"client-{suffix}", system_id, [str(project)], profiles or ["standard"])
        discovery = self.hub.registry.discover(system_id)
        dossier = {
            "purpose": "Synthetic new-project acceptance",
            "hierarchy": {"repositories": [item["repo_id"] for item in discovery["repositories"]], "components": []},
            "provenance": [{"source": "synthetic-test"}],
            "quality_gates": registration["policy"]["gates"],
        }
        version = self.hub.dossier.create_draft(system_id, dossier)
        self.hub.dossier.approve(system_id, version, "test-owner")
        self.hub.registry.approve_system(system_id, "test-owner")
        task_id = f"task-{suffix}"
        task = self.hub.tasks.create(system_id, "Create a tested calculator add function", registration["policy"]["classification"], registration["policy"]["policy_hash"], task_id)
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            task = self.hub.tasks.transition(task_id, state)
        self.hub.orchestrator.plan(task_id)
        repo_id = discovery["repositories"][0]["repo_id"]
        workspace = self.hub.workspaces.create(task_id, [repo_id])
        self.hub.tasks.transition(task_id, "WORKSPACES_READY", evidence=[workspace["manifest_hash"]])
        return project, repo_id, Path(workspace["repositories"][0]["workspace"]), task_id, system_id

    @staticmethod
    def good_driver(task_id: str, prompt: str, attempt: int, role: str):
        request = json.loads(prompt)
        repo_id = request["repositories"][0]
        app = "def add(left, right):\n    return left + right\n"
        test = "import unittest\nfrom app import add\n\nclass AddTests(unittest.TestCase):\n    def test_adds(self):\n        self.assertEqual(add(2, 3), 5)\n"
        return {
            "status": "ok",
            "changed_paths": [f"{repo_id}:app.py", f"{repo_id}:tests/test_app.py"],
            "operations": [
                {"repo_id": repo_id, "path": "app.py", "action": "write", "content": app, "expected_hash": None, "executable": False},
                {"repo_id": repo_id, "path": "tests/test_app.py", "action": "write", "content": test, "expected_hash": None, "executable": False},
            ],
        }


class OrchestrationTests(ReleaseBase):
    def test_new_project_completes_from_both_local_adapter_identities(self):
        for surface, adapter in (("codex", "codex-local"), ("claude", "claude-local")):
            with self.subTest(surface=surface):
                _, repo_id, workspace, task_id, _ = self.task(surface)
                report = self.hub.orchestrator.complete(task_id, self.good_driver, adapter=adapter)
                self.assertTrue(report["verified"], report)
                self.assertEqual(report["task"]["state"], "VERIFIED")
                self.assertEqual(len(report["quality_runs"]), 2)
                self.assertTrue((workspace / "app.py").is_file())
                self.assertTrue((workspace / "tests" / "test_app.py").is_file())
                self.assertEqual(len(report["releases"]), 1)
                self.assertTrue(report["audit_valid"])

    def test_failed_logic_is_repaired_then_fully_verified(self):
        _, _, workspace, task_id, _ = self.task("repair")

        def repair_driver(task_id, prompt, attempt, role):
            request = json.loads(prompt)
            repo_id = request["repositories"][0]
            test = "import unittest\nfrom app import ready\nclass T(unittest.TestCase):\n    def test_ready(self): self.assertTrue(ready())\n"
            if attempt == 1:
                app = "def ready():\n    return False\n"
                return {"status": "ok", "changed_paths": [f"{repo_id}:app.py", f"{repo_id}:tests/test_app.py"], "operations": [
                    {"repo_id": repo_id, "path": "app.py", "action": "write", "content": app, "expected_hash": None, "executable": False},
                    {"repo_id": repo_id, "path": "tests/test_app.py", "action": "write", "content": test, "expected_hash": None, "executable": False},
                ]}
            current = next(item for item in request["context_files"] if item["path"] == "app.py")
            app = "def ready():\n    return True\n"
            return {"status": "ok", "changed_paths": [f"{repo_id}:app.py"], "operations": [
                {"repo_id": repo_id, "path": "app.py", "action": "write", "content": app, "expected_hash": current["hash"], "executable": False},
            ]}

        report = self.hub.orchestrator.complete(task_id, repair_driver, adapter="codex-local")
        self.assertTrue(report["verified"], report)
        self.assertEqual(len(report["implementation_attempts"]), 2)
        self.assertEqual(len(report["quality_runs"]), 3)
        self.assertIn("return True", (workspace / "app.py").read_text())

    def test_blocked_worker_pauses_precisely_and_is_not_verified(self):
        _, _, _, task_id, _ = self.task("pause")
        def blocked(*_):
            return {"status": "blocked", "reason": "business rule for rounding is missing", "changed_paths": []}
        report = self.hub.orchestrator.complete(task_id, blocked, adapter="codex-local")
        self.assertFalse(report["verified"])
        self.assertEqual(report["task"]["state"], "PAUSED_INPUT")
        self.assertIn("rounding", report["task"]["reason"])
        with self.assertRaises(PolicyDenied):
            self.hub.tasks.resume(task_id, "VERIFIED")
        with self.assertRaises(PolicyDenied):
            self.hub.tasks.resume(task_id, "PRODUCTION_APPROVAL")

    def test_typed_operations_reject_secret_traversal_and_stale_writes(self):
        _, repo_id, workspace, task_id, _ = self.task("unsafe")
        self.hub.tasks.transition(task_id, "LOCAL_IMPLEMENTING")
        base = {"status": "ok", "changed_paths": [f"{repo_id}:../outside.py"], "operations": [{"repo_id": repo_id, "path": "../outside.py", "action": "write", "content": "safe = True\n", "expected_hash": None}]}
        with self.assertRaises(PolicyDenied):
            self.hub.orchestrator.applier.apply(task_id, "codex-local", 1, "a" * 64, base)
        secret = {"status": "ok", "changed_paths": [f"{repo_id}:app.py"], "operations": [{"repo_id": repo_id, "path": "app.py", "action": "write", "content": "api_key='hh_test_CANARY_REJECTED'\n", "expected_hash": None}]}
        with self.assertRaises(PolicyDenied):
            self.hub.orchestrator.applier.apply(task_id, "codex-local", 1, "a" * 64, secret)
        (workspace / "app.py").write_text("existing=True\n", encoding="utf-8")
        stale = {"status": "ok", "changed_paths": [f"{repo_id}:app.py"], "operations": [{"repo_id": repo_id, "path": "app.py", "action": "write", "content": "existing=False\n", "expected_hash": "0" * 64}]}
        with self.assertRaises(PolicyDenied):
            self.hub.orchestrator.applier.apply(task_id, "codex-local", 1, "a" * 64, stale)

    def test_cancel_releases_writer_lease_but_preserves_workspace(self):
        _, _, workspace, task_id, _ = self.task("cancel-release")
        self.assertTrue(any(item["owner"] == task_id for item in self.hub.leases.list()))
        cancelled = self.hub.cancel_task(task_id)
        self.assertEqual(cancelled["state"], "CANCELLED")
        self.assertGreaterEqual(cancelled["released_leases"], 1)
        self.assertTrue(workspace.is_dir())
        self.assertFalse(any(item["owner"] == task_id for item in self.hub.leases.list()))


class CloudBoundaryTests(ReleaseBase):
    def bundle(self):
        _, repo_id, workspace, task_id, system_id = self.task("cloud")
        (workspace / "review.py").write_text("def answer():\n    return 42\n", encoding="utf-8")
        (workspace / ".env").write_text("api_key=hh_test_CANARY_ADJACENT_NOT_REAL\n", encoding="utf-8")
        bundle = self.hub.egress.build(task_id, "codex-cloud", [{"repo_id": repo_id, "path": "review.py"}])
        self.hub.egress.approve(bundle["bundle_id"], "review-owner")
        profile = {
            "provider": "codex-cloud", "mode": "synthetic", "endpoint": "https://synthetic.invalid",
            "account_type": "api", "account_identity": "synthetic-account", "max_turns": 2,
            "max_seconds": 30, "max_cost_usd": 0,
        }
        proposed = self.hub.provider_profiles.propose(system_id, profile, "provider-owner")
        self.hub.provider_profiles.approve(proposed["profile_id"], "provider-owner")
        return task_id, bundle["bundle_id"]

    def test_synthetic_cloud_receives_only_sealed_selected_files(self):
        task_id, bundle_id = self.bundle()
        def transport(payload, request):
            encoded = json.dumps(payload)
            self.assertNotIn("ADJACENT", encoded)
            self.assertEqual([item["path"] for item in payload["files"]], ["review.py"])
            self.assertEqual(payload["ambient_paths"], [])
            self.assertIsNone(payload["credentials"])
            return {"decision": "approve", "findings": [], "patch": None, "turns": 1}
        result = self.hub.cloud.run(bundle_id, "review", transport)
        self.assertEqual(result["result"]["decision"], "approve")
        self.assertFalse(result["preflight"]["private_repository_access"])

    def test_consumer_account_and_unapproved_live_route_fail_closed(self):
        with self.assertRaises(PolicyDenied):
            ProviderProfile.from_dict({"provider": "codex-cloud", "mode": "live", "endpoint": "https://api.openai.com", "account_type": "consumer", "account_identity": "bad", "max_turns": 1, "max_seconds": 30, "max_cost_usd": 1})
        _, bundle_id = self.bundle()
        system_id = self.hub.egress.get(bundle_id)["system_id"]
        live = {"provider": "codex-cloud", "mode": "live", "endpoint": "https://api.openai.com", "account_type": "api", "account_identity": "synthetic-account", "max_turns": 2, "max_seconds": 30, "max_cost_usd": 1.0}
        proposed = self.hub.provider_profiles.propose(system_id, live, "provider-owner")
        self.hub.provider_profiles.approve(proposed["profile_id"], "provider-owner", enable_live=True)
        with self.assertRaises(PolicyDenied):
            self.hub.cloud.preflight(bundle_id)

    def test_quota_failure_preserves_task_and_bundle(self):
        task_id, bundle_id = self.bundle()
        before = self.hub.tasks.get(task_id)["state"]
        def quota(*_):
            raise TimeoutError("synthetic quota")
        with self.assertRaises(Exception):
            self.hub.cloud.run(bundle_id, "review", quota)
        self.assertEqual(self.hub.tasks.get(task_id)["state"], before)
        self.assertEqual(self.hub.egress.get(bundle_id)["status"], "approved")


class DeploymentAndOperationsTests(ReleaseBase):
    def verified(self, suffix: str):
        _, _, _, task_id, _ = self.task(suffix)
        report = self.hub.orchestrator.complete(task_id, self.good_driver, adapter="synthetic-acceptance")
        self.assertTrue(report["verified"])
        return task_id

    @staticmethod
    def healthy(request):
        return {"status": "healthy", "health_gates": ["synthetic-smoke", "error-rate"], "artifact_ids": request["artifact_ids"], "rollback_id": None}

    def test_staging_canary_production_and_human_acceptance(self):
        task_id = self.verified("deploy")
        staging = self.hub.deployments.deploy_staging(task_id, "synthetic-ci", self.healthy)
        self.assertEqual(staging["status"], "healthy")
        approval = self.hub.deployments.approve_production(task_id, "release-owner")
        production = self.hub.deployments.promote(task_id, approval["approval_id"], "synthetic-ci", self.healthy)
        self.assertEqual(production["status"], "healthy")
        accepted = self.hub.deployments.accept(task_id, "release-owner")
        self.assertEqual(accepted["state"], "HUMAN_ACCEPTED")

    def test_failed_canary_rolls_back_and_never_claims_verified_production(self):
        task_id = self.verified("rollback")
        self.hub.deployments.deploy_staging(task_id, "synthetic-ci", self.healthy)
        approval = self.hub.deployments.approve_production(task_id, "release-owner")
        calls = []
        def transport(request):
            calls.append(request["action"])
            if request["action"] == "rollback":
                return {"status": "rolled-back", "health_gates": ["rollback-complete"], "artifact_ids": request["artifact_ids"], "rollback_id": "rb-synthetic"}
            return {"status": "failed", "health_gates": ["canary-error-rate"], "artifact_ids": request["artifact_ids"], "rollback_id": None}
        production = self.hub.deployments.promote(task_id, approval["approval_id"], "synthetic-ci", transport)
        self.assertEqual(production["status"], "rolled-back")
        self.assertEqual(calls, ["canary", "rollback"])
        self.assertEqual(self.hub.tasks.get(task_id)["state"], "FAILED_INFRA")

    def test_operations_backup_sbom_access_review_and_retention_preview(self):
        task_id = self.verified("ops")
        backup = self.hub.operations.backup()
        verified = self.hub.operations.verify_backup(backup["backup_id"])
        self.assertTrue(verified["valid"])
        restored = self.hub.operations.restore_backup(backup["backup_id"], self.root / "restored-runtime")
        self.assertTrue(restored["valid"])
        source_root = self.root / "sbom-source"
        (source_root / "runtime" / "workspaces").mkdir(parents=True)
        (source_root / "pyproject.toml").write_text("[project]\nname = \"synthetic\"\n", encoding="utf-8")
        (source_root / "runtime" / "workspaces" / "package.json").write_text("{}\n", encoding="utf-8")
        sbom = self.hub.operations.sbom(source_root)
        self.assertEqual(sbom["network_calls"], 0)
        self.assertEqual([item["path"] for item in sbom["manifests"]], ["pyproject.toml"])
        review = self.hub.operations.access_review()
        self.assertEqual(review["runtime_mode"], "0o700")
        retention = self.hub.operations.retention(30, execute=False)
        self.assertFalse(retention["execute"])
        security = self.hub.operations.security_evaluation()
        self.assertTrue(security["passed"])
        self.assertFalse(security["regulated_readiness_claim"])
        self.assertTrue(self.hub.audit.verify())

    def test_cli_like_deploy_without_project_adapter_fails_closed(self):
        task_id = self.verified("no-adapter")
        with self.assertRaises(AuthorizationRequired):
            self.hub.deployments.deploy_staging(task_id, "missing", None)


class ModifierTests(ReleaseBase):
    @staticmethod
    def definition(name="medical-local", **overrides):
        value = {
            "name": name,
            "description": "Synthetic situation-specific workflow",
            "classification_floor": "R2",
            "preferred_local_adapter": "codex-local",
            "allowed_local_models": ["qwen3:1.7b"],
            "max_repairs": 2,
            "context_bytes": 16384,
            "add_required_gates": [],
            "research_mode": "cache-only",
            "cloud_review": "disabled",
            "deployment_posture": "none",
            "deny_actions": ["cloud-review", "live-research", "production", "staging"],
            "component_ids": [],
            "path_prefixes": [],
        }
        value.update(overrides)
        return value

    def approved_modifier(self, system_id, value):
        proposed = self.hub.modifiers.propose(system_id, value, "modifier-owner")
        return self.hub.modifiers.approve(proposed["modifier_id"], "modifier-owner")

    def test_each_project_can_bind_a_distinct_immutable_modifier(self):
        _, _, _, task_a, system_a = self.task("modifier-a", profiles=["healthcare"])
        _, _, _, task_b, system_b = self.task("modifier-b", profiles=["legal"])
        mod_a = self.approved_modifier(system_a, self.definition("medical-local"))
        mod_b = self.approved_modifier(system_b, self.definition("legal-review", classification_floor="R4", preferred_local_adapter="claude-local", allowed_local_models=["gemma3:1b"], cloud_review="required", deny_actions=["live-research", "production", "staging"]))
        self.hub.modifiers.bind(task_a, mod_a["modifier_id"])
        self.hub.modifiers.bind(task_b, mod_b["modifier_id"])
        self.assertEqual(self.hub.modifiers.for_task(task_a)["modifier"]["classification_floor"], "R2")
        self.assertEqual(self.hub.modifiers.for_task(task_b)["modifier"]["classification_floor"], "R4")
        with self.assertRaises(PolicyDenied):
            self.hub.modifiers.bind(task_a, mod_b["modifier_id"])

    def test_modifier_cannot_add_authority_or_exceed_managed_limits(self):
        _, _, _, _, system_id = self.task("modifier-invalid")
        invalid = self.definition()
        invalid["enable_cloud"] = True
        with self.assertRaises(ValidationError):
            self.hub.modifiers.propose(system_id, invalid, "modifier-owner")
        with self.assertRaises(ValidationError):
            self.hub.modifiers.propose(system_id, self.definition(max_repairs=99), "modifier-owner")
        with self.assertRaises(ValidationError):
            self.hub.modifiers.propose(system_id, self.definition(path_prefixes=["../sibling"]), "modifier-owner")

    def test_modifier_extra_quality_gate_fails_closed_until_implemented(self):
        _, _, _, task_id, system_id = self.task("modifier-gate")
        modifier = self.approved_modifier(system_id, self.definition("special-gate", classification_floor="R1", add_required_gates=["custom-safety-review"], deny_actions=[]))
        self.hub.modifiers.bind(task_id, modifier["modifier_id"])
        report = self.hub.orchestrator.complete(task_id, self.good_driver, adapter="codex-local", max_repairs=0)
        self.assertFalse(report["verified"])
        self.assertEqual(report["task"]["state"], "BLOCKED_QUALITY")
        latest = self.hub.quality.latest(task_id, "targeted")
        self.assertIn("custom-safety-review", latest["missing_gates"])

    def test_modifier_research_cloud_and_deployment_denials_are_enforced(self):
        _, _, _, task_id, system_id = self.task("modifier-deny")
        modifier = self.approved_modifier(system_id, self.definition("local-only", classification_floor="R1"))
        self.hub.modifiers.bind(task_id, modifier["modifier_id"])
        resolved = self.hub.research.resolve(task_id, "python documentation")
        self.assertEqual(resolved["mode"], "local-only")
        self.assertFalse(resolved["network_used"])
        report = self.hub.orchestrator.complete(task_id, self.good_driver, adapter="codex-local")
        self.assertTrue(report["verified"])
        with self.assertRaises(PolicyDenied):
            self.hub.deployments.deploy_staging(task_id, "synthetic-ci", self.healthy if hasattr(self, "healthy") else lambda _: {})


class ProjectLocalIntegrationTests(ReleaseBase):
    def test_install_is_explicit_project_local_and_preserves_existing_vscode_tasks(self):
        project, _, _, _, system_id = self.task("integration")
        sibling = self.root / "not-selected"
        sibling.mkdir()
        vscode = project / ".vscode"
        vscode.mkdir()
        (vscode / "tasks.json").write_text(json.dumps({"version": "2.0.0", "tasks": [{"label": "Existing", "type": "shell", "command": "true"}], "inputs": []}), encoding="utf-8")
        hub_entry = Path(__file__).resolve().parents[1] / "hub.py"
        result = self.hub.integrations.install(system_id, project, hub_entry, self.hub.database.layout.root)
        self.assertTrue(result["project_local"])
        self.assertFalse(result["global_configuration_modified"])
        self.assertFalse(result["agents_or_claude_md_created"])
        self.assertFalse((project / "AGENTS.md").exists())
        self.assertFalse((project / "CLAUDE.md").exists())
        self.assertFalse(any(sibling.iterdir()))
        labels = {item["label"] for item in json.loads((vscode / "tasks.json").read_text())["tasks"]}
        self.assertIn("Existing", labels)
        self.assertIn("Hybrid: Run and Verify", labels)
        self.assertTrue((project / ".agents" / "skills" / "hybrid-run" / "SKILL.md").is_file())
        self.assertTrue((project / ".claude" / "skills" / "hybrid-run" / "SKILL.md").is_file())

    def test_install_rejects_unregistered_sibling(self):
        project, _, _, _, system_id = self.task("integration-deny")
        sibling = self.root / "sibling"
        sibling.mkdir()
        with self.assertRaises(PolicyDenied):
            self.hub.integrations.install(system_id, sibling, Path(__file__).resolve().parents[1] / "hub.py", self.hub.database.layout.root)


class FullCLIEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.hub_entry = Path(__file__).resolve().parents[1] / "hub.py"
        self.fake_ollama = self.root / "ollama"
        self.fake_ollama.write_text(
            "#!/usr/bin/env python3\n"
            "import json,sys\n"
            "if sys.argv[1] == 'list':\n"
            " print('NAME ID SIZE MODIFIED')\n print('synthetic:1 abc 1GB now')\n"
            "elif sys.argv[1] == 'run':\n"
            " req=json.loads(sys.argv[3]); repo=req['repositories'][0]\n"
            " app='def multiply(a, b):\\n    return a * b\\n'\n"
            " test='import unittest\\nfrom app import multiply\\nclass T(unittest.TestCase):\\n    def test_multiply(self): self.assertEqual(multiply(3, 4), 12)\\n'\n"
            " out={'status':'ok','changed_paths':[repo+':app.py',repo+':tests/test_app.py'],'operations':[{'repo_id':repo,'path':'app.py','action':'write','content':app,'expected_hash':None,'executable':False},{'repo_id':repo,'path':'tests/test_app.py','action':'write','content':test,'expected_hash':None,'executable':False}]}\n"
            " print(json.dumps(out,separators=(',',':')))\n",
            encoding="utf-8",
        )
        os.chmod(self.fake_ollama, 0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, runtime: Path, *arguments, expected=0):
        completed = subprocess.run(["python3", str(self.hub_entry), "--runtime", str(runtime), *arguments], capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, expected, completed.stdout + completed.stderr)
        return json.loads(completed.stdout)

    def test_one_command_new_project_reaches_verified_from_codex_and_claude_surfaces(self):
        for surface, adapter in (("codex", "codex-local"), ("claude", "claude-local")):
            with self.subTest(surface=surface):
                runtime = self.root / f"runtime-{surface}"
                project = self.root / f"new-project-{surface}"
                project.mkdir()
                (project / "README.md").write_text("# Brand new synthetic project\n", encoding="utf-8")
                git_repo(project)
                system = f"cli-{surface}"
                initialized = self.invoke(runtime, "system", "init", "--id", system, "--client", f"client-{surface}", "--name", system, "--root", str(project), "--profile", "standard", "--purpose", "Fresh synthetic CLI acceptance")
                self.invoke(runtime, "system", "approve", system, "--approver", "cli-owner")
                result = self.invoke(runtime, "run", "Create a multiplication function with tests", "--system", system, "--task-id", f"task-{surface}", "--through", "verified", "--adapter", adapter, "--model", "synthetic:1", "--executable", str(self.fake_ollama), "--max-repairs", "0")
                self.assertTrue(result["result"]["verified"], result)
                self.assertEqual(result["result"]["task"]["state"], "VERIFIED")
                self.assertEqual(len(result["result"]["quality_runs"]), 2)
                self.assertTrue(result["result"]["audit_valid"])

    def test_failed_model_preflight_creates_no_task_or_workspace(self):
        runtime = self.root / "runtime-preflight"
        project = self.root / "preflight-project"
        project.mkdir()
        (project / "README.md").write_text("# Preflight synthetic\n", encoding="utf-8")
        git_repo(project)
        self.invoke(runtime, "system", "init", "--id", "preflight-system", "--client", "preflight-client", "--name", "Preflight", "--root", str(project), "--profile", "standard", "--purpose", "Preflight ordering")
        self.invoke(runtime, "system", "approve", "preflight-system", "--approver", "cli-owner")
        failed = self.invoke(runtime, "run", "Do not create this task", "--system", "preflight-system", "--task-id", "task-missing-model", "--through", "verified", "--model", "missing:9", "--executable", str(self.fake_ollama), expected=2)
        self.assertEqual(failed["error"], "AdapterError")
        status = self.invoke(runtime, "status", "task-missing-model", expected=2)
        self.assertEqual(status["error"], "ValidationError")
        self.assertFalse((runtime / "workspaces" / "task-missing-model").exists())


if __name__ == "__main__":
    unittest.main()

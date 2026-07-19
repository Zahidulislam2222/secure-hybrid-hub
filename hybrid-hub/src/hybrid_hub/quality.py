from __future__ import annotations

import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditLog, SECRET_PATTERNS, sanitize
from .dossier import DossierStore
from .errors import AdapterError, ConflictError, PolicyDenied, ValidationError
from .policy import compose
from .storage import Database
from .topology import Topology
from .util import canonical_json, require_id, sha256_bytes, sha256_json, utc_now


COMMAND_ID = re.compile(r"^[a-z][a-z0-9._-]{1,63}$")
SAFE_ARGUMENT = re.compile(r"^[^\x00\r\n]{1,4096}$")
TEST_PATH = re.compile(r"(^|/)(tests?|specs?)(/|$)|(^|/)(test_|.*[._-](?:test|spec)\.)", re.I)
CONTRACT_PATH = re.compile(r"(?:openapi|swagger|schema|contract).*(?:\.json|\.ya?ml)$", re.I)
MIGRATION_PATH = re.compile(r"(^|/)(migrations?|db/migrate)(/|$)", re.I)
SKIP_PATTERN = re.compile(r"(?i)(?:@(?:unittest\.)?skip|pytest\.mark\.skip|\bskipTest\s*\(|\bx(?:it|fail)\b)")
DISABLE_PATTERN = re.compile(r"(?i)(?:pragma:\s*no\s*cover|#\s*nosec|scanner.{0,20}(?:disable|off)|coverage.{0,20}(?:disable|omit)|--no-verify)")
ASSERT_PATTERN = re.compile(r"\bassert\b|\bself\.assert[A-Z]")
DESTRUCTIVE_SQL = re.compile(r"(?i)\b(?:DROP\s+(?:TABLE|COLUMN|DATABASE)|TRUNCATE\s+TABLE|DELETE\s+FROM\s+[^;\n]+(?:;|$))")
SENSITIVE_CONTENT = [
    ("synthetic-canary", re.compile(r"hh_test_CANARY_[A-Z0-9_]+")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("credential-assignment", re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|password|client[_-]?secret)\s*[:=]\s*(?!(?:os\.|process\.env|env\[|getenv\(|settings\.|config\.|vault\.|secret_ref|['\"]?(?:placeholder|redacted|test[-_])))['\"]?[^\s,'\";]{8,}")),
]
CLASSIFICATION_CONTENT = {
    "phi-scan": re.compile(r"(?i)\b(?:patient|medical record|diagnosis|health plan)\b.{0,40}\b(?:name|id|dob|address|email|phone)\b"),
    "pii-scan": re.compile(r"(?i)\b(?:ssn|social security|passport|national id)\b\s*[:=]?\s*[A-Z0-9-]{5,}"),
    "privilege-scan": re.compile(r"(?i)\b(?:attorney[- ]client privileged|privileged legal communication|work product)\b"),
}
CONTROL_ONLY_GATES = {
    "selected-source-only", "human-egress-approval", "no-project-egress",
    "staging", "canary", "rollback", "human-production-approval",
}
BUILTIN_GATES = {"secret-scan", "test-integrity", "parse", "unit", *CLASSIFICATION_CONTENT}


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    gate: str
    argv: tuple[str, ...]
    repository_id: str | None = None
    component: str | None = None
    cwd: str = "."
    scope: str = "both"
    timeout_seconds: int = 300
    workspace_scope: str = "repository"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CommandSpec":
        if not isinstance(value, dict):
            raise ValidationError("quality command must be an object")
        allowed = {"command_id", "gate", "argv", "repository_id", "component", "cwd", "scope", "timeout_seconds", "workspace_scope"}
        if set(value) - allowed:
            raise ValidationError("quality command contains unknown fields")
        command_id = value.get("command_id")
        gate = value.get("gate")
        argv = value.get("argv")
        cwd = value.get("cwd", ".")
        scope = value.get("scope", "both")
        timeout = value.get("timeout_seconds", 300)
        workspace_scope = value.get("workspace_scope", "repository")
        if not isinstance(command_id, str) or not COMMAND_ID.fullmatch(command_id):
            raise ValidationError("invalid quality command ID")
        if not isinstance(gate, str) or not COMMAND_ID.fullmatch(gate):
            raise ValidationError("invalid quality gate")
        if not isinstance(argv, list) or not argv or len(argv) > 64 or any(not isinstance(item, str) or not SAFE_ARGUMENT.fullmatch(item) for item in argv):
            raise ValidationError("quality argv must be a bounded non-empty string list")
        if not isinstance(cwd, str) or not cwd or Path(cwd).is_absolute() or ".." in Path(cwd).parts:
            raise ValidationError("quality cwd must stay inside its workspace")
        if scope not in {"targeted", "full", "both"}:
            raise ValidationError("quality command scope is invalid")
        if not isinstance(timeout, int) or timeout < 1 or timeout > 1800:
            raise ValidationError("quality command timeout is invalid")
        if workspace_scope not in {"repository", "system"}:
            raise ValidationError("quality workspace_scope is invalid")
        if workspace_scope == "system" and (value.get("repository_id") is not None or value.get("component") is not None):
            raise ValidationError("system-scoped quality commands cannot name one repository or component")
        for field in ("repository_id", "component"):
            item = value.get(field)
            if item is not None:
                require_id(item, field)
        return cls(command_id, gate, tuple(argv), value.get("repository_id"), value.get("component"), cwd, scope, timeout, workspace_scope)

    def as_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id, "gate": self.gate, "argv": list(self.argv),
            "repository_id": self.repository_id, "component": self.component,
            "cwd": self.cwd, "scope": self.scope, "timeout_seconds": self.timeout_seconds,
            "workspace_scope": self.workspace_scope,
        }


class QualityRegistry:
    def __init__(self, database: Database, audit: AuditLog, dossier: DossierStore):
        self.database = database
        self.audit = audit
        self.dossier = dossier

    def propose(self, system_id: str, commands: list[dict[str, Any]], proposed_by: str) -> dict[str, Any]:
        require_id(proposed_by, "proposer")
        specs = [CommandSpec.from_dict(item) for item in commands]
        if not specs or len(specs) > 128:
            raise ValidationError("quality command set must contain 1 to 128 commands")
        ids = [item.command_id for item in specs]
        if len(ids) != len(set(ids)):
            raise ValidationError("quality command IDs must be unique")
        with self.database.transaction() as connection:
            system = connection.execute("SELECT 1 FROM systems WHERE system_id=?", (system_id,)).fetchone()
            if not system:
                raise ValidationError("unknown system")
            payload = [item.as_dict() for item in specs]
            digest = sha256_json(payload)
            command_set_id = f"qcs-{uuid.uuid4().hex[:16]}"
            connection.execute(
                "INSERT INTO quality_command_sets VALUES(?,?,?,?,?,?,?,?,NULL)",
                (command_set_id, system_id, "pending", self.database.json(payload), digest, proposed_by, None, utc_now()),
            )
            self.audit.append("quality.commands-proposed", {"command_set_id": command_set_id, "command_set_hash": digest, "command_count": len(specs), "proposed_by": proposed_by}, system_id=system_id, connection=connection)
        return {"command_set_id": command_set_id, "system_id": system_id, "status": "pending", "command_set_hash": digest, "commands": payload}

    def approve(self, command_set_id: str, approver: str) -> dict[str, Any]:
        require_id(approver, "approver")
        with self.database.connect() as connection:
            candidate = connection.execute("SELECT * FROM quality_command_sets WHERE command_set_id=?", (command_set_id,)).fetchone()
        if not candidate or candidate["status"] != "pending":
            raise ConflictError("pending quality command set unavailable")
        commands = json.loads(candidate["commands_json"])
        proposal = self.dossier.propose(candidate["system_id"], {"approved_commands": {"command_set_id": command_set_id, "command_set_hash": candidate["command_set_hash"], "commands": commands}}, task_id=None)
        self.dossier.decide(proposal["proposal_id"], approver, True)
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM quality_command_sets WHERE command_set_id=?", (command_set_id,)).fetchone()
            if not row or row["status"] != "pending":
                raise ConflictError("pending quality command set unavailable")
            connection.execute("UPDATE quality_command_sets SET status='superseded' WHERE system_id=? AND status='approved'", (row["system_id"],))
            connection.execute("UPDATE quality_command_sets SET status='approved',approved_by=?,approved_at=? WHERE command_set_id=?", (approver, utc_now(), command_set_id))
            self.audit.append("quality.commands-approved", {"command_set_id": command_set_id, "command_set_hash": row["command_set_hash"], "approver": approver}, system_id=row["system_id"], connection=connection)
        return self.get(command_set_id)

    def get(self, command_set_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM quality_command_sets WHERE command_set_id=?", (command_set_id,)).fetchone()
        if not row:
            raise ValidationError("unknown quality command set")
        result = dict(row)
        result["commands"] = json.loads(result.pop("commands_json"))
        return result

    def active(self, system_id: str) -> list[CommandSpec]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT commands_json FROM quality_command_sets WHERE system_id=? AND status='approved' ORDER BY approved_at DESC LIMIT 1", (system_id,)).fetchone()
        return [] if not row else [CommandSpec.from_dict(item) for item in json.loads(row[0])]


class QualityRunner:
    MAX_FILES = 100_000
    MAX_SCAN_BYTES = 512 * 1024 * 1024
    MAX_FILE_BYTES = 32 * 1024 * 1024
    MAX_OUTPUT_BYTES = 2 * 1024 * 1024

    def __init__(self, database: Database, audit: AuditLog, dossier: DossierStore, registry: QualityRegistry):
        self.database = database
        self.audit = audit
        self.dossier = dossier
        self.registry = registry
        self._sandbox_script = Path(__file__).with_name("sandbox_exec.py").resolve()
        self.modifiers = None

    def run(self, task_id: str, scope: str) -> dict[str, Any]:
        if scope not in {"targeted", "full"}:
            raise ValidationError("quality scope must be targeted or full")
        if self.database.emergency_stopped():
            raise PolicyDenied("emergency stop is active")
        task, system = self._task_context(task_id)
        allowed_states = {"LOCAL_IMPLEMENTING", "TARGETED_TESTING", "LOCAL_REPAIRING"} if scope == "targeted" else {"FULL_QUALITY_GATES", "LOCAL_FIXING"}
        if task["state"] not in allowed_states:
            raise PolicyDenied(f"task state {task['state']} does not permit {scope} quality gates")
        repositories = self._workspace_repositories(task_id, system["system_id"])
        specs = self.registry.active(system["system_id"])
        policy = compose(json.loads(system["profiles_json"]))
        run_id = f"qr-{uuid.uuid4().hex[:16]}"
        results: list[dict[str, Any]] = []
        observed_gates: set[str] = set()
        affected_by_repository: dict[str, list[str]] = {}
        preflight_safe = True
        for repository in repositories:
            affected = self._affected_components(repository)
            affected_by_repository[repository["repo_id"]] = sorted(affected)
            builtins = self._builtin_checks(repository, policy.gates)
            results.extend(builtins)
            preflight_safe = preflight_safe and all(item["passed"] for item in builtins)
            observed_gates.update(item["gate"] for item in builtins if item["passed"])
            selected = [item for item in specs if item.workspace_scope == "repository" and item.scope in {scope, "both"} and item.repository_id in {None, repository["repo_id"]} and (scope == "full" or item.component is None or item.component in affected)]
            selected.extend(self._python_commands(repository, scope, {item.gate for item in selected}))
            if any(not item["passed"] for item in builtins):
                for spec in selected:
                    results.append({"command_id": spec.command_id, "gate": spec.gate, "repository_id": repository["repo_id"], "component": spec.component, "passed": False, "exit_code": None, "duration_ms": 0, "evidence_digest": None, "findings": ["command not executed because a pre-execution safety gate failed"]})
            else:
                for spec in selected:
                    result = self._execute(repository, spec, run_id)
                    results.append(result)
                    if result["passed"]:
                        observed_gates.add(result["gate"])
        system_specs = [item for item in specs if item.workspace_scope == "system" and item.scope in {scope, "both"}]
        for spec in system_specs:
            if not preflight_safe:
                results.append({"command_id": spec.command_id, "gate": spec.gate, "repository_id": None, "covered_repositories": [item["repo_id"] for item in repositories], "component": None, "passed": False, "exit_code": None, "duration_ms": 0, "evidence_digest": None, "findings": ["command not executed because a pre-execution safety gate failed"]})
                continue
            result = self._execute_system(repositories, spec, run_id)
            results.append(result)
            if result["passed"]:
                observed_gates.add(result["gate"])
        required = {gate for gate in policy.gates if gate not in CONTROL_ONLY_GATES}
        modifier_row = self.modifiers.for_task(task_id) if self.modifiers else None
        if modifier_row:
            required.update(modifier_row["modifier"]["add_required_gates"])
        required.update({"secret-scan", "test-integrity", "parse", "unit"})
        missing_by_repository: dict[str, list[str]] = {}
        for repository in repositories:
            repository_passes = {item["gate"] for item in results if item["passed"] and (item.get("repository_id") == repository["repo_id"] or repository["repo_id"] in item.get("covered_repositories", []))}
            repository_missing = sorted(required - repository_passes)
            missing_by_repository[repository["repo_id"]] = repository_missing
            for gate in repository_missing:
                results.append({"command_id": f"required-{gate}", "gate": gate, "repository_id": repository["repo_id"], "passed": False, "exit_code": None, "duration_ms": 0, "evidence_digest": None, "findings": ["required gate has no passing approved implementation for this repository"]})
        missing = sorted({gate for gates in missing_by_repository.values() for gate in gates})
        passed = bool(results) and all(item["passed"] for item in results)
        summary = {
            "schema_version": "1.0.0", "run_id": run_id, "task_id": task_id,
            "system_id": system["system_id"], "scope": scope, "passed": passed,
            "policy_hash": task["policy_hash"], "required_gates": sorted(required),
            "missing_gates": missing, "gates": results, "created_at": utc_now(),
            "execution_isolation": "disposable-snapshot+landlock+user/pid/ipc/uts/network-namespaces; no external egress",
            "affected_components": affected_by_repository,
            "missing_gates_by_repository": missing_by_repository,
        }
        encoded = canonical_json(summary)
        evidence_digest = self.database.put_artifact(encoded)
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO quality_runs VALUES(?,?,?,?,?,?,?)", (run_id, task_id, scope, int(passed), self.database.json(summary), evidence_digest, utc_now()))
            checkpoint = self.dossier.checkpoint(system["system_id"], f"quality-{run_id}", task["state"], {"actor": "quality-runner", "policy_hash": task["policy_hash"], "classification": task["classification"], "evidence": [evidence_digest], "quality_scope": scope, "quality_passed": passed, "unresolved_risks": [] if passed else ["one or more deterministic quality gates failed"]}, task_id=task_id, connection=connection)
            self.audit.append("quality.completed", {"run_id": run_id, "scope": scope, "passed": passed, "evidence_digest": evidence_digest, "checkpoint_hash": checkpoint, "gate_count": len(results)}, system_id=system["system_id"], task_id=task_id, connection=connection)
        return {**summary, "evidence_digest": evidence_digest}

    def latest(self, task_id: str, scope: str | None = None) -> dict[str, Any]:
        if scope:
            query = "SELECT * FROM quality_runs WHERE task_id=? AND scope=? ORDER BY created_at DESC LIMIT 1"
            values: tuple[Any, ...] = (task_id, scope)
        else:
            query = "SELECT * FROM quality_runs WHERE task_id=? ORDER BY created_at DESC LIMIT 1"
            values = (task_id,)
        with self.database.connect() as connection:
            row = connection.execute(query, values).fetchone()
        if not row:
            raise ValidationError("quality evidence unavailable")
        return {**json.loads(row["summary_json"]), "evidence_digest": row["evidence_digest"]}

    def _task_context(self, task_id: str):
        with self.database.connect() as connection:
            task = connection.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not task:
                raise ValidationError("unknown task")
            system = connection.execute("SELECT * FROM systems WHERE system_id=?", (task["system_id"],)).fetchone()
        if task["cancelled"] or not system or not system["approved"]:
            raise PolicyDenied("task unavailable, cancelled, or system disabled")
        return dict(task), dict(system)

    def _workspace_repositories(self, task_id: str, system_id: str) -> list[dict[str, Any]]:
        manifest_path = self.database.layout.workspaces / task_id / "workspace-manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise ValidationError("broker workspace manifest unavailable")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("task_id") != task_id or manifest.get("system_id") != system_id:
            raise PolicyDenied("workspace manifest scope mismatch")
        expected_hash = manifest.pop("manifest_hash", None)
        if expected_hash != sha256_json(manifest):
            raise PolicyDenied("workspace manifest integrity check failed")
        repositories = manifest.get("repositories")
        if not isinstance(repositories, list) or not repositories:
            raise ValidationError("workspace manifest has no repositories")
        result = []
        for item in repositories:
            workspace = Path(item["workspace"]).resolve(strict=True)
            task_root = (self.database.layout.workspaces / task_id).resolve(strict=True)
            if not workspace.is_relative_to(task_root) or workspace.is_symlink():
                raise PolicyDenied("workspace escapes broker task root")
            result.append({**item, "workspace_path": workspace})
        return result

    def _builtin_checks(self, repository: dict[str, Any], policy_gates: tuple[str, ...]) -> list[dict[str, Any]]:
        return [
            *self._content_scans(repository, policy_gates),
            self._integrity_scan(repository),
            self._contract_scan(repository),
        ]

    def _affected_components(self, repository: dict[str, Any]) -> set[str]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT components_json FROM repositories WHERE repo_id=?", (repository["repo_id"],)).fetchone()
        if not row:
            raise ValidationError("registered repository metadata unavailable")
        components = json.loads(row[0])
        component_ids = {item["id"] for item in components}
        root = repository["workspace_path"]
        changed_paths = self._changed_paths(repository)
        if not changed_paths:
            return component_ids
        direct: set[str] = set()
        outside = False
        for relative in changed_paths:
            matches = [item["id"] for item in components if item.get("path", ".") == "." or relative == item.get("path") or relative.startswith(str(item.get("path", "")).rstrip("/") + "/")]
            if matches:
                direct.update(matches)
            else:
                outside = True
        if outside or not direct:
            return component_ids
        topology_text = subprocess.run(["git", "-C", str(root), "show", f"{repository['base_commit']}:hub-topology.json"], capture_output=True, text=True, timeout=15, check=False)
        if topology_text.returncode:
            return direct
        try:
            definition = json.loads(topology_text.stdout)
            return set(Topology(definition.get("components", components), definition.get("dependencies", [])).affected(direct))
        except (json.JSONDecodeError, ValidationError):
            return component_ids

    def _files(self, root: Path):
        count = 0
        total = 0
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if ".git" in relative.parts:
                continue
            if path.is_symlink():
                raise PolicyDenied(f"quality scan rejects symlink: {relative.as_posix()}")
            if not path.is_file():
                continue
            count += 1
            if count > self.MAX_FILES:
                raise PolicyDenied("quality scan file-count limit exceeded")
            size = path.stat().st_size
            total += size
            if size > self.MAX_FILE_BYTES or total > self.MAX_SCAN_BYTES:
                raise PolicyDenied("quality scan byte limit exceeded")
            yield path, relative.as_posix(), size

    def _content_scans(self, repository: dict[str, Any], policy_gates: tuple[str, ...]) -> list[dict[str, Any]]:
        findings: dict[str, list[str]] = {"secret-scan": []}
        gates = [gate for gate in CLASSIFICATION_CONTENT if gate in policy_gates]
        findings.update({gate: [] for gate in gates})
        changed_paths = self._changed_paths(repository)
        for path, relative, _ in self._files(repository["workspace_path"]):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                if relative in changed_paths:
                    findings["secret-scan"].append(f"changed binary or non-UTF-8 file requires explicit approval: {relative}")
                continue
            if Path(relative).name.startswith(".env") and not Path(relative).name.endswith((".example", ".sample", ".template")):
                findings["secret-scan"].append(f"environment-value file is forbidden in a coding workspace: {relative}")
            for detector, pattern in SENSITIVE_CONTENT:
                if pattern.search(text):
                    findings["secret-scan"].append(f"{detector} finding: {relative}")
            for gate in gates:
                if CLASSIFICATION_CONTENT[gate].search(text):
                    findings[gate].append(f"{gate} finding: {relative}")
        return [self._builtin_result(f"builtin-{gate}", gate, repository["repo_id"], gate_findings) for gate, gate_findings in findings.items()]

    def _changed_paths(self, repository: dict[str, Any]) -> set[str]:
        root = repository["workspace_path"]
        changed = self._git(root, ["diff", "--name-only", "--no-renames", repository["base_commit"], "--"])
        untracked = self._git(root, ["ls-files", "--others", "--exclude-standard"])
        return {line.strip() for line in (changed + "\n" + untracked).splitlines() if line.strip()}

    def _integrity_scan(self, repository: dict[str, Any]) -> dict[str, Any]:
        root = repository["workspace_path"]
        base = repository["base_commit"]
        status = self._git(root, ["diff", "--name-status", "--no-renames", base, "--"])
        diff = self._git(root, ["diff", "--unified=0", "--no-ext-diff", base, "--"])
        findings: list[str] = []
        for line in status.splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2 and parts[0] == "D" and TEST_PATH.search(parts[1]):
                findings.append(f"test deletion detected: {parts[1]}")
        removed_assertions = 0
        for line in diff.splitlines():
            if line.startswith("+") and not line.startswith("+++") and (SKIP_PATTERN.search(line) or DISABLE_PATTERN.search(line)):
                findings.append("new test/scanner disabling directive detected")
            if line.startswith("-") and not line.startswith("---") and ASSERT_PATTERN.search(line):
                removed_assertions += 1
        if removed_assertions:
            findings.append(f"removed test assertions detected: {removed_assertions}")
        return self._builtin_result("builtin-test-integrity", "test-integrity", repository["repo_id"], findings)

    def _contract_scan(self, repository: dict[str, Any]) -> dict[str, Any]:
        root = repository["workspace_path"]
        base = repository["base_commit"]
        findings: list[str] = []
        status = self._git(root, ["diff", "--name-status", "--no-renames", base, "--"])
        for line in status.splitlines():
            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue
            action, relative = parts
            if action == "D" and CONTRACT_PATH.search(relative):
                findings.append(f"contract deletion detected: {relative}")
            if MIGRATION_PATH.search(relative):
                current = root / relative
                if current.is_file():
                    try:
                        if DESTRUCTIVE_SQL.search(current.read_text(encoding="utf-8")):
                            findings.append(f"destructive migration requires approval: {relative}")
                    except UnicodeDecodeError:
                        findings.append(f"non-text migration rejected: {relative}")
            if action == "M" and relative.lower().endswith(".json") and CONTRACT_PATH.search(relative):
                self._compare_json_contract(root, base, relative, findings)
        return self._builtin_result("builtin-contract-compatibility", "contract-compatibility", repository["repo_id"], findings)

    def _compare_json_contract(self, root: Path, base: str, relative: str, findings: list[str]) -> None:
        old_result = subprocess.run(["git", "-C", str(root), "show", f"{base}:{relative}"], capture_output=True, text=True, timeout=15, check=False)
        if old_result.returncode:
            return
        try:
            old = json.loads(old_result.stdout)
            new = json.loads((root / relative).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            findings.append(f"invalid JSON contract: {relative}")
            return
        old_properties = set(old.get("properties", {})) if isinstance(old, dict) else set()
        new_properties = set(new.get("properties", {})) if isinstance(new, dict) else set()
        if old_properties - new_properties:
            findings.append(f"JSON contract removed properties: {relative}")
        if set(new.get("required", [])) - set(old.get("required", [])):
            findings.append(f"JSON contract added required fields: {relative}")
        old_paths = old.get("paths", {}) if isinstance(old, dict) else {}
        new_paths = new.get("paths", {}) if isinstance(new, dict) else {}
        if set(old_paths) - set(new_paths):
            findings.append(f"OpenAPI contract removed paths: {relative}")
        for path, methods in old_paths.items():
            if path in new_paths and isinstance(methods, dict) and isinstance(new_paths[path], dict) and set(methods) - set(new_paths[path]):
                findings.append(f"OpenAPI contract removed operations: {relative}:{path}")

    @staticmethod
    def _builtin_result(command_id: str, gate: str, repository_id: str, findings: list[str]) -> dict[str, Any]:
        return {"command_id": command_id, "gate": gate, "repository_id": repository_id, "passed": not findings, "exit_code": 0 if not findings else 1, "duration_ms": 0, "evidence_digest": None, "findings": sorted(set(findings))}

    def _python_commands(self, repository: dict[str, Any], scope: str, configured_gates: set[str]) -> list[CommandSpec]:
        root = repository["workspace_path"]
        has_python = any(path.suffix == ".py" for path, _, _ in self._files(root))
        if not has_python:
            return []
        specs = []
        if "parse" not in configured_gates:
            specs.append(CommandSpec("builtin-python-parse", "parse", ("$PYTHON", "-m", "compileall", "-q", "."), repository["repo_id"], scope=scope, timeout_seconds=120))
        if "unit" not in configured_gates and (root / "tests").is_dir():
            specs.append(CommandSpec("builtin-python-unit", "unit", ("$PYTHON", "-m", "unittest", "discover", "-s", "tests", "-v"), repository["repo_id"], scope=scope, timeout_seconds=600))
        return specs

    def _execute(self, repository: dict[str, Any], spec: CommandSpec, run_id: str) -> dict[str, Any]:
        root = repository["workspace_path"]
        source_cwd = (root / spec.cwd).resolve(strict=True)
        if not source_cwd.is_relative_to(root):
            raise PolicyDenied("quality command cwd escapes workspace")
        executable, arguments = self._resolve_argv(spec.argv)
        if executable.lower().endswith(".exe"):
            raise PolicyDenied("Windows executables cannot be network-isolated by the WSL quality runner")
        unshare = shutil.which("unshare", path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        if not unshare:
            raise PolicyDenied("kernel namespace isolation executable is unavailable")
        execution_root = self.database.layout.evidence / "executions" / run_id / repository["repo_id"] / spec.command_id
        snapshot = execution_root / "workspace"
        home = execution_root / "home"
        execution_root.mkdir(parents=True, exist_ok=False, mode=0o700)
        self._copy_snapshot(root, snapshot)
        home.mkdir(parents=True, exist_ok=True, mode=0o700)
        cwd = snapshot / source_cwd.relative_to(root)
        if not self._isolation_available(unshare, execution_root):
            raise PolicyDenied("kernel namespace and Landlock isolation is unavailable")
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(home),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1", "NO_PROXY": "*", "no_proxy": "*",
        }
        command = [unshare, "--user", "--map-root-user", "--net", "--pid", "--ipc", "--uts", "--fork", sys.executable, str(self._sandbox_script), "--allow-root", str(execution_root), "--", executable, *arguments]
        exit_code, duration_ms, evidence_digest, output_hash, findings = self._run_bounded(command, cwd, environment, spec.timeout_seconds)
        return {"command_id": spec.command_id, "gate": spec.gate, "repository_id": repository["repo_id"], "component": spec.component, "passed": exit_code == 0 and not findings, "exit_code": exit_code, "duration_ms": duration_ms, "evidence_digest": evidence_digest, "output_hash": output_hash, "findings": findings}

    def _run_bounded(self, command: list[str], cwd: Path, environment: dict[str, str], timeout: int) -> tuple[int, int, str, str, list[str]]:
        started = __import__("time").monotonic()
        with tempfile.NamedTemporaryFile(dir=self.database.layout.evidence, prefix="quality-", delete=False) as output:
            output_path = Path(output.name)
            try:
                process = subprocess.Popen(command, cwd=cwd, env=environment, stdout=output, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=self._limits(timeout))
                try:
                    exit_code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
                    exit_code = 124
            except OSError as exc:
                raise AdapterError(f"quality command launch failed: {type(exc).__name__}") from exc
        try:
            raw = output_path.read_bytes()[: self.MAX_OUTPUT_BYTES + 1]
        finally:
            output_path.unlink(missing_ok=True)
        truncated = len(raw) > self.MAX_OUTPUT_BYTES
        raw = raw[: self.MAX_OUTPUT_BYTES]
        text = raw.decode("utf-8", errors="replace")
        safe_text = sanitize(text)
        encoded = safe_text.encode("utf-8")
        evidence_digest = self.database.put_artifact(encoded, "text/plain; charset=utf-8")
        duration_ms = int((__import__("time").monotonic() - started) * 1000)
        findings = []
        if exit_code:
            findings.append(f"approved command exited {exit_code}")
        if truncated:
            findings.append("command output exceeded evidence limit")
        return exit_code, duration_ms, evidence_digest, sha256_bytes(encoded), findings

    def _execute_system(self, repositories: list[dict[str, Any]], spec: CommandSpec, run_id: str) -> dict[str, Any]:
        execution_root = self.database.layout.evidence / "executions" / run_id / "system" / spec.command_id
        snapshot = execution_root / "workspace"
        home = execution_root / "home"
        execution_root.mkdir(parents=True, exist_ok=False, mode=0o700)
        snapshot.mkdir(mode=0o700)
        for repository in repositories:
            self._copy_snapshot(repository["workspace_path"], snapshot / repository["repo_id"])
        home.mkdir(mode=0o700)
        cwd = (snapshot / spec.cwd).resolve(strict=True)
        if not cwd.is_relative_to(snapshot):
            raise PolicyDenied("system quality command cwd escapes combined snapshot")
        executable, arguments = self._resolve_argv(spec.argv)
        if executable.lower().endswith(".exe"):
            raise PolicyDenied("Windows executables cannot be isolated by the WSL quality runner")
        unshare = shutil.which("unshare", path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        if not unshare or not self._isolation_available(unshare, execution_root):
            raise PolicyDenied("kernel namespace and Landlock isolation is unavailable")
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1", "NO_PROXY": "*", "no_proxy": "*"}
        command = [unshare, "--user", "--map-root-user", "--net", "--pid", "--ipc", "--uts", "--fork", sys.executable, str(self._sandbox_script), "--allow-root", str(execution_root), "--", executable, *arguments]
        exit_code, duration_ms, evidence_digest, output_hash, findings = self._run_bounded(command, cwd, environment, spec.timeout_seconds)
        return {"command_id": spec.command_id, "gate": spec.gate, "repository_id": None, "covered_repositories": [item["repo_id"] for item in repositories], "component": None, "passed": exit_code == 0 and not findings, "exit_code": exit_code, "duration_ms": duration_ms, "evidence_digest": evidence_digest, "output_hash": output_hash, "findings": findings}

    def _copy_snapshot(self, source: Path, destination: Path) -> None:
        destination.mkdir(parents=True, mode=0o700)
        for path, relative, _ in self._files(source):
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(path, target)
            os.chmod(target, path.stat().st_mode & 0o777)

    @staticmethod
    def _resolve_argv(argv: tuple[str, ...]) -> tuple[str, list[str]]:
        first = argv[0]
        if first == "$PYTHON":
            executable = str(Path(sys.executable).resolve())
        elif Path(first).is_absolute():
            executable = str(Path(first).resolve(strict=True))
        else:
            resolved = shutil.which(first, path="/usr/local/bin:/usr/bin:/bin")
            if not resolved:
                raise ValidationError(f"approved quality executable is unavailable: {first}")
            executable = str(Path(resolved).resolve(strict=True))
        if not Path(executable).is_file():
            raise ValidationError("approved quality executable is not a file")
        return executable, list(argv[1:])

    def _isolation_available(self, unshare: str, allow_root: Path) -> bool:
        true_executable = shutil.which("true", path="/usr/bin:/bin")
        if not true_executable:
            return False
        result = subprocess.run([unshare, "--user", "--map-root-user", "--net", "--pid", "--ipc", "--uts", "--fork", sys.executable, str(self._sandbox_script), "--allow-root", str(allow_root), "--", true_executable], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
        return result.returncode == 0

    @staticmethod
    def _limits(timeout: int):
        def apply() -> None:
            resource.setrlimit(resource.RLIMIT_CPU, (timeout + 5, timeout + 5))
            resource.setrlimit(resource.RLIMIT_FSIZE, (QualityRunner.MAX_OUTPUT_BYTES + 4096, QualityRunner.MAX_OUTPUT_BYTES + 4096))
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
            resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
            limit = 4 * 1024 * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        return apply

    @staticmethod
    def _git(root: Path, arguments: list[str]) -> str:
        completed = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, text=True, timeout=30, check=False, env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
        if completed.returncode:
            raise AdapterError(f"Git quality inspection failed: {completed.stderr.strip()[:200]}")
        return completed.stdout

from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any, Callable

from .audit import AuditLog, SECRET_PATTERNS
from .dossier import DossierStore
from .errors import AdapterError, PolicyDenied, ValidationError
from .guided import EvidencePacketBuilder, GuidedPlanStore
from .quality import QualityRunner
from .state import TaskManager
from .storage import Database
from .util import atomic_write, canonical_json, sha256_bytes, sha256_json, utc_now


Driver = Callable[[str, str, int, str], dict[str, Any]]
MAX_OPERATIONS = 200
MAX_OPERATION_BYTES = 1_048_576
MAX_ATTEMPT_BYTES = 8_388_608
FORBIDDEN_PARTS = {".git", ".hg", ".svn", ".hub", "runtime", "secrets"}
SAFE_TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".toml", ".yaml", ".yml", ".md", ".txt",
    ".html", ".css", ".scss", ".sql", ".sh", ".ps1", ".java", ".kt", ".go", ".rs", ".rb",
    ".php", ".cs", ".xml", ".graphql", ".proto", ".ini", ".cfg", ".env.example", "",
}


class ImplementationApplier:
    """Applies typed model proposals without granting a model shell access."""

    def __init__(self, database: Database, audit: AuditLog, dossier: DossierStore):
        self.database = database
        self.audit = audit
        self.dossier = dossier

    def apply(self, task_id: str, adapter: str, attempt: int, request_hash: str, result: dict[str, Any], *, allowed_scope: dict[str, list[str]] | None = None, exact_scope: bool = False) -> dict[str, Any]:
        if adapter not in {"codex-local", "claude-local", "synthetic-acceptance"}:
            raise ValidationError("implementation adapter identity is invalid")
        if result.get("status") not in {"ok", "blocked", "failed"}:
            raise AdapterError("implementation status is invalid")
        if result["status"] != "ok":
            reason = result.get("reason")
            if not isinstance(reason, str) or not reason.strip() or len(reason.encode()) > 4096:
                raise AdapterError("blocked implementation must include a bounded reason")
            return {"status": result["status"], "reason": reason, "changed_paths": [], "diff_hash": sha256_json([])}
        operations = result.get("operations")
        changed_paths = result.get("changed_paths")
        if not isinstance(operations, list) or not operations or len(operations) > MAX_OPERATIONS:
            raise AdapterError("implementation operations are missing or exceed the limit")
        if not isinstance(changed_paths, list) or any(not isinstance(item, str) for item in changed_paths):
            raise AdapterError("implementation changed_paths is invalid")
        repositories = self._workspaces(task_id)
        normalized: list[dict[str, Any]] = []
        total = 0
        seen: set[tuple[str, str]] = set()
        for operation in operations:
            item = self._validate_operation(operation, repositories)
            if allowed_scope is not None:
                prefixes = allowed_scope.get(item["repo_id"], [])
                in_scope = item["path"] in prefixes if exact_scope else any(self._within_prefix(item["path"], prefix) for prefix in prefixes)
                if not prefixes or not in_scope:
                    raise PolicyDenied("implementation operation exceeds its guided packet path scope")
            key = (item["repo_id"], item["path"])
            if key in seen:
                raise AdapterError("implementation contains duplicate path operations")
            seen.add(key)
            if item["action"] == "write":
                total += len(item["content"].encode("utf-8"))
            if total > MAX_ATTEMPT_BYTES:
                raise AdapterError("implementation attempt exceeds the byte limit")
            normalized.append(item)
        proposed_paths = sorted(f"{item['repo_id']}:{item['path']}" for item in normalized)
        if sorted(changed_paths) != proposed_paths:
            raise AdapterError("changed_paths does not exactly match typed operations")
        backups: list[tuple[Path, bytes | None, int | None]] = []
        try:
            for item in normalized:
                root = repositories[item["repo_id"]]
                target = root / item["path"]
                existed = target.is_file()
                backups.append((target, target.read_bytes() if existed else None, target.stat().st_mode if existed else None))
                if item["action"] == "delete":
                    target.unlink()
                else:
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    mode = 0o755 if item.get("executable") else 0o644
                    atomic_write(target, item["content"].encode("utf-8"), mode)
            diff_hash = self._diff_hash(repositories)
        except BaseException:
            for target, content, mode in reversed(backups):
                if content is None:
                    target.unlink(missing_ok=True)
                else:
                    atomic_write(target, content, (mode or 0o644) & 0o777)
            raise
        result_hash = sha256_json({"status": "ok", "operations": normalized, "changed_paths": proposed_paths})
        attempt_id = f"ia-{uuid.uuid4().hex[:16]}"
        with self.database.transaction() as connection:
            task = connection.execute("SELECT system_id,classification,policy_hash FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not task:
                raise ValidationError("unknown task")
            connection.execute("INSERT INTO implementation_attempts VALUES(?,?,?,?,?,?,?,?,?,?)", (attempt_id, task_id, adapter, attempt, "applied", request_hash, result_hash, self.database.json(proposed_paths), diff_hash, utc_now()))
            checkpoint = self.dossier.checkpoint(task["system_id"], f"implementation-{attempt}", "LOCAL_IMPLEMENTING", {"actor": adapter, "policy_hash": task["policy_hash"], "classification": task["classification"], "evidence": [result_hash, diff_hash], "changed_paths": proposed_paths, "unresolved_risks": []}, task_id=task_id, connection=connection)
            self.audit.append("implementation.applied", {"attempt_id": attempt_id, "adapter": adapter, "attempt": attempt, "result_hash": result_hash, "diff_hash": diff_hash, "changed_paths": proposed_paths, "checkpoint_hash": checkpoint}, system_id=task["system_id"], task_id=task_id, connection=connection)
        return {"status": "ok", "attempt_id": attempt_id, "changed_paths": proposed_paths, "diff_hash": diff_hash, "result_hash": result_hash}

    @staticmethod
    def _within_prefix(path: str, prefix: str) -> bool:
        return prefix == "." or path == prefix or path.startswith(prefix.rstrip("/") + "/")

    def _validate_operation(self, value: Any, repositories: dict[str, Path]) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise AdapterError("implementation operation must be an object")
        allowed = {"repo_id", "path", "action", "content", "expected_hash", "executable"}
        if set(value) - allowed:
            raise AdapterError("implementation operation contains unknown fields")
        repo_id, relative_text, action = value.get("repo_id"), value.get("path"), value.get("action")
        if repo_id not in repositories or not isinstance(relative_text, str) or not relative_text:
            raise PolicyDenied("implementation operation is outside task repository scope")
        relative = Path(relative_text)
        if relative.is_absolute() or ".." in relative.parts or any(part.lower() in FORBIDDEN_PARTS for part in relative.parts):
            raise PolicyDenied("implementation operation path is forbidden")
        root = repositories[repo_id]
        target = root / relative
        parent = target.parent.resolve(strict=True) if target.parent.exists() else self._nearest_existing(target.parent)
        if not parent.is_relative_to(root) or target.is_symlink():
            raise PolicyDenied("implementation path escapes through a symlink")
        if action not in {"write", "delete"}:
            raise AdapterError("implementation action must be write or delete")
        current = target.read_bytes() if target.is_file() else None
        expected = value.get("expected_hash")
        actual_hash = sha256_bytes(current) if current is not None else None
        if expected != actual_hash:
            raise PolicyDenied("implementation expected_hash does not match current content")
        if action == "delete":
            if current is None:
                raise PolicyDenied("implementation cannot delete a missing file")
            return {"repo_id": repo_id, "path": relative.as_posix(), "action": "delete", "expected_hash": expected}
        content = value.get("content")
        if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_OPERATION_BYTES or "\x00" in content:
            raise AdapterError("implementation content is not bounded UTF-8 text")
        suffix = target.suffix.lower()
        if suffix not in SAFE_TEXT_SUFFIXES and target.name not in {"Dockerfile", "Makefile", "Procfile"}:
            raise PolicyDenied("implementation file type is not approved for model writing")
        for pattern in SECRET_PATTERNS:
            if pattern.search(content):
                raise PolicyDenied("implementation proposal contains credential-like material")
        executable = value.get("executable", False)
        if not isinstance(executable, bool):
            raise AdapterError("implementation executable marker is invalid")
        return {"repo_id": repo_id, "path": relative.as_posix(), "action": "write", "content": content, "expected_hash": expected, "executable": executable}

    @staticmethod
    def _nearest_existing(path: Path) -> Path:
        candidate = path
        while not candidate.exists():
            if candidate.parent == candidate:
                raise PolicyDenied("implementation parent cannot be resolved")
            candidate = candidate.parent
        return candidate.resolve(strict=True)

    def _workspaces(self, task_id: str) -> dict[str, Path]:
        manifest_path = self.database.layout.workspaces / task_id / "workspace-manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise ValidationError("task workspace manifest unavailable")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest.pop("manifest_hash", None)
        if expected != sha256_json(manifest):
            raise PolicyDenied("task workspace manifest integrity failed")
        task_root = (self.database.layout.workspaces / task_id).resolve(strict=True)
        result: dict[str, Path] = {}
        for item in manifest["repositories"]:
            path = Path(item["workspace"]).resolve(strict=True)
            if not path.is_relative_to(task_root):
                raise PolicyDenied("workspace escapes task root")
            result[item["repo_id"]] = path
        return result

    @staticmethod
    def _diff_hash(repositories: dict[str, Path]) -> str:
        material = []
        for repo_id, root in sorted(repositories.items()):
            diff = subprocess.run(["git", "-C", str(root), "diff", "--binary", "HEAD", "--"], capture_output=True, timeout=30, check=False).stdout
            untracked = subprocess.run(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z"], capture_output=True, timeout=30, check=False).stdout
            untracked_hashes = []
            for relative in untracked.decode("utf-8").split("\0"):
                if relative:
                    untracked_hashes.append((relative, sha256_bytes((root / relative).read_bytes())))
            material.append({"repo_id": repo_id, "diff": sha256_bytes(diff), "untracked": untracked_hashes})
        return sha256_json(material)


class Orchestrator:
    def __init__(self, database: Database, audit: AuditLog, dossier: DossierStore, tasks: TaskManager, quality: QualityRunner):
        self.database = database
        self.audit = audit
        self.dossier = dossier
        self.tasks = tasks
        self.quality = quality
        self.applier = ImplementationApplier(database, audit, dossier)
        self.modifiers = None
        self.leases = None
        self.guided_plans: GuidedPlanStore | None = None
        self.research_packets: EvidencePacketBuilder | None = None

    def submit_guided_plan(self, task_id: str, template: dict[str, Any], source: str) -> dict[str, Any]:
        if not self.guided_plans:
            raise ValidationError("guided plan store is unavailable")
        return self.guided_plans.submit(task_id, template, source)

    def complete_guided(self, task_id: str, driver: Driver, *, adapter: str, max_repairs: int = 3) -> dict[str, Any]:
        if not self.guided_plans or not self.research_packets:
            raise ValidationError("guided orchestration is unavailable")
        if not 0 <= max_repairs <= 3:
            raise ValidationError("repair limit exceeds managed policy")
        plan_row = self.guided_plans.get(task_id)
        task = self.tasks.get(task_id)
        if task["state"] != "WORKSPACES_READY":
            raise PolicyDenied("guided completion requires WORKSPACES_READY")
        modifier_row = self.modifiers.for_task(task_id) if self.modifiers else None
        if modifier_row:
            max_repairs = min(max_repairs, modifier_row["modifier"]["max_repairs"])
        workspace_ids = set(self.applier._workspaces(task_id))
        planned_ids = {repo_id for item in plan_row["plan"]["packets"] for repo_id in item["repository_ids"]}
        if planned_ids != workspace_ids:
            raise PolicyDenied("guided plan repository scope does not exactly match task workspaces")
        self.tasks.transition(task_id, "LOCAL_IMPLEMENTING", evidence=[plan_row["plan_hash"]])
        global_attempt = 0
        applied_results: list[dict[str, Any]] = []
        last_packet_quality: dict[str, Any] | None = None
        for packet_row in plan_row["packets"]:
            packet = packet_row["packet"]
            if packet_row["status"] == "passed":
                continue
            evidence = self.research_packets.build(task_id, packet)
            if packet["research_required"] and not evidence["items"]:
                self.tasks.transition(task_id, "PAUSED_AUTH", evidence=[evidence["evidence_packet_hash"]], reason=f"guided packet {packet['packet_id']} requires approved official research evidence")
                return self.final_report(task_id)
            self.guided_plans.update_packet(task_id, packet["packet_id"], "research-ready", attempts=packet_row["attempts"], result_hash=evidence["evidence_packet_hash"])
            allowed_scope: dict[str, list[str]] = {}
            for deliverable in packet["deliverables"]:
                allowed_scope.setdefault(deliverable["repo_id"], []).append(deliverable["path"])
            seen: set[str] = set()
            packet_failure: dict[str, Any] | None = None
            for packet_attempt in range(1, max_repairs + 2):
                global_attempt += 1
                role = "packet-implementation" if packet_attempt == 1 else "packet-repair"
                self.guided_plans.update_packet(task_id, packet["packet_id"], "implementing" if packet_attempt == 1 else "repairing", attempts=packet_attempt)
                try:
                    operations = []
                    prompt_hashes = []
                    repositories = self.applier._workspaces(task_id)
                    for deliverable in packet["deliverables"]:
                        prompt = self._guided_prompt(task_id, plan_row["plan"], packet, deliverable, evidence, role, packet_attempt, packet_failure)
                        prompt_hashes.append(sha256_bytes(prompt.encode("utf-8")))
                        result = driver(task_id, prompt, global_attempt, f"{role}:file")
                        if result.get("status") == "blocked":
                            self.tasks.transition(task_id, "PAUSED_INPUT", reason=result.get("reason", f"packet {packet['packet_id']} requires input"))
                            return self.final_report(task_id)
                        if result.get("status") != "ok":
                            raise AdapterError("guided local file worker returned failed")
                        content = result.get("content")
                        if not isinstance(content, str) or not content or "\x00" in content:
                            raise AdapterError("guided local file worker omitted complete file content")
                        target = repositories[deliverable["repo_id"]] / deliverable["path"]
                        expected_hash = sha256_bytes(target.read_bytes()) if target.is_file() else None
                        operations.append({"repo_id": deliverable["repo_id"], "path": deliverable["path"], "action": "write", "content": content, "expected_hash": expected_hash, "executable": False})
                    changed_paths = [f"{item['repo_id']}:{item['path']}" for item in operations]
                    result = {"status": "ok", "changed_paths": changed_paths, "operations": operations}
                    request_hash = sha256_json(prompt_hashes)
                    applied = self.applier.apply(task_id, adapter, global_attempt, request_hash, result, allowed_scope=allowed_scope, exact_scope=True)
                except PolicyDenied as exc:
                    self.tasks.transition(task_id, "BLOCKED_POLICY", reason=str(exc))
                    return self.final_report(task_id)
                except (AdapterError, TimeoutError, OSError) as exc:
                    detail = str(exc)[:300]
                    self.audit.append("guided-packet.worker-failed", {"packet_id": packet["packet_id"], "attempt": packet_attempt, "error": type(exc).__name__, "safe_detail": detail}, system_id=task["system_id"], task_id=task_id)
                    packet_failure = {"scope": "worker-contract", "evidence_digest": sha256_json({"error": type(exc).__name__, "detail": detail}), "missing_gates": ["valid-typed-output"], "gates": [], "safe_detail": detail}
                    if packet_attempt > max_repairs:
                        self.guided_plans.update_packet(task_id, packet["packet_id"], "blocked", attempts=packet_attempt, result_hash=packet_failure["evidence_digest"])
                        self.tasks.transition(task_id, "BLOCKED_QUALITY", reason=f"guided packet {packet['packet_id']} exhausted bounded worker attempts")
                        return self.final_report(task_id)
                    continue
                if applied["diff_hash"] in seen:
                    self.guided_plans.update_packet(task_id, packet["packet_id"], "blocked", attempts=packet_attempt, result_hash=applied["result_hash"])
                    self.tasks.transition(task_id, "BLOCKED_QUALITY", reason=f"guided packet {packet['packet_id']} made no progress")
                    return self.final_report(task_id)
                seen.add(applied["diff_hash"])
                packet_quality = self.quality.run(task_id, "targeted")
                if packet_quality["passed"]:
                    self.guided_plans.update_packet(task_id, packet["packet_id"], "passed", attempts=packet_attempt, result_hash=applied["result_hash"], quality_digest=packet_quality["evidence_digest"])
                    applied_results.append(applied)
                    last_packet_quality = packet_quality
                    break
                packet_failure = self._model_failure(packet_quality)
                if packet_attempt > max_repairs:
                    self.guided_plans.update_packet(task_id, packet["packet_id"], "blocked", attempts=packet_attempt, result_hash=applied["result_hash"], quality_digest=packet_quality["evidence_digest"])
                    self.tasks.transition(task_id, "BLOCKED_QUALITY", reason=f"guided packet {packet['packet_id']} exhausted bounded repairs")
                    return self.final_report(task_id)
        if not applied_results or last_packet_quality is None:
            self.tasks.transition(task_id, "BLOCKED_QUALITY", reason="guided plan produced no verified implementation packets")
            return self.final_report(task_id)
        self.tasks.transition(task_id, "TARGETED_TESTING", evidence=[last_packet_quality["evidence_digest"]])
        targeted = self.quality.run(task_id, "targeted")
        if not targeted["passed"]:
            self.tasks.transition(task_id, "BLOCKED_QUALITY", reason="cross-packet targeted verification failed")
            return self.final_report(task_id)
        self.tasks.transition(task_id, "FULL_QUALITY_GATES", evidence=[targeted["evidence_digest"]])
        full = self.quality.run(task_id, "full")
        if not full["passed"]:
            self.tasks.transition(task_id, "BLOCKED_QUALITY", reason="cross-packet full verification failed")
            return self.final_report(task_id)
        aggregate = {
            "status": "ok",
            "result_hash": sha256_json([item["result_hash"] for item in applied_results]),
            "diff_hash": sha256_json([item["diff_hash"] for item in applied_results]),
        }
        return self._verify(task_id, aggregate, targeted, full)

    def _model_failure(self, quality: dict[str, Any]) -> dict[str, Any]:
        diagnostics = []
        remaining = 8_000
        with self.database.connect() as connection:
            for gate in quality.get("gates", []):
                digest = gate.get("evidence_digest")
                if gate.get("passed") or not digest or remaining <= 0:
                    continue
                row = connection.execute("SELECT relative_path FROM artifacts WHERE digest=?", (digest,)).fetchone()
                if not row:
                    continue
                path = self.database.layout.artifacts / row["relative_path"]
                try:
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                for pattern in SECRET_PATTERNS:
                    if pattern.search(text):
                        raise PolicyDenied("sanitized quality evidence failed the model-context secret check")
                encoded = text.encode("utf-8")[:remaining]
                remaining -= len(encoded)
                diagnostics.append({"gate": gate.get("gate"), "command_id": gate.get("command_id"), "evidence_digest": digest, "output": encoded.decode("utf-8", errors="ignore")})
        return {**quality, "sanitized_diagnostics": diagnostics}

    def _guided_prompt(self, task_id: str, plan: dict[str, Any], packet: dict[str, Any], deliverable: dict[str, str], evidence: dict[str, Any], role: str, attempt: int, failure: dict[str, Any] | None) -> str:
        task = self.tasks.get(task_id)
        dossier = self.dossier.current(task["system_id"])
        repositories = self.applier._workspaces(task_id)
        context = []
        modifier_row = self.modifiers.for_task(task_id) if self.modifiers else None
        budget = min(8_000, modifier_row["modifier"]["context_bytes"] if modifier_row else 8_000)
        for repo_id in packet["repository_ids"]:
            root = repositories[repo_id]
            for relative in packet["context_paths"][repo_id]:
                candidates = [root / relative] if (root / relative).is_file() else sorted((root / relative).rglob("*")) if (root / relative).is_dir() else []
                for path in candidates:
                    if not path.is_file() or path.is_symlink() or ".git" in path.parts:
                        continue
                    try:
                        data = path.read_bytes()
                        text = data.decode("utf-8")
                    except (OSError, UnicodeDecodeError):
                        continue
                    if len(data) > 32_000 or len(data) > budget:
                        continue
                    for pattern in SECRET_PATTERNS:
                        if pattern.search(text):
                            raise PolicyDenied(f"local model context blocked credential-like content in {path.name}")
                    context.append({"repo_id": repo_id, "path": path.relative_to(root).as_posix(), "hash": sha256_bytes(data), "content": text})
                    budget -= len(data)
                    if budget < 1024:
                        break
        failure_summary = None
        if failure:
            failure_summary = {"scope": failure.get("scope"), "evidence_digest": failure.get("evidence_digest"), "missing_gates": failure.get("missing_gates", []), "safe_detail": failure.get("safe_detail"), "findings": [finding for gate in failure.get("gates", []) for finding in gate.get("findings", [])][:20]}
        def render() -> str:
            lines = [
                "YOU ARE A BOUNDED FILE-PATCH WORKER. DO THE TASK; DO NOT EXPLAIN THE TASK.",
                "Return only the complete raw source text for the one requested file. Do not use JSON, Markdown fences, a filename header, or prose.",
                f"PACKET ID: {packet['packet_id']}", f"ROLE: {role}", f"ATTEMPT: {attempt}",
                f"GENERATE THIS ONE FILE NOW: {deliverable['repo_id']}:{deliverable['path']}",
                f"FILE PURPOSE: {deliverable['purpose']}",
                f"EXACT HIGH-MODEL FILE INSTRUCTIONS: {deliverable['instructions']}",
                "RELATED PACKET FILES (paths only; generate none of them in this reply):",
            ]
            for item in packet["deliverables"]:
                lines.append(f"- {item['repo_id']}:{item['path']} — {item['purpose']}")
            if context:
                lines.append("CURRENT FILES (facts; preserve their hashes for edits):")
                for item in context:
                    lines.extend([f"FILE {item['repo_id']}:{item['path']} SHA256={item['hash']}", item["content"], "END FILE"])
            if packet["research_guidance"]:
                lines.append("HIGH-MODEL RESEARCH GUIDANCE (apply these implementation facts):")
                lines.extend(f"- {item}" for item in packet["research_guidance"])
            if evidence["items"]:
                lines.append("OFFICIAL RESEARCH PROVENANCE (raw web text is intentionally withheld from this coding model):")
                for item in evidence["items"]:
                    lines.append(f"SOURCE {item['source_url']} HASH={item['content_hash']} RETRIEVED={item['retrieved_at']} INJECTION_DETECTED={item['prompt_injection_detected']}")
            if failure_summary:
                lines.extend(["PREVIOUS ATTEMPT FAILURE (fix it now):", canonical_json(failure_summary).decode("utf-8")])
                for item in failure.get("sanitized_diagnostics", []) if failure else []:
                    lines.extend([f"SANITIZED {item['gate']} OUTPUT HASH={item['evidence_digest']}", item["output"], "END DIAGNOSTIC"])
            lines.extend([
                f"The response must be real complete working source for {deliverable['path']}, not an example or placeholder.",
                "RULES: Generate only the one requested file. Do not include secrets. Do not weaken or skip tests. Do not explain. End the file by writing <<END_FILE>> on its own line; the broker removes that marker.",
                "NOW RETURN ONLY THE COMPLETE FILE CONTENT, THEN <<END_FILE>>.",
            ])
            return "\n".join(lines)

        encoded = render().encode("utf-8")
        while len(encoded) > 30_000 and context:
            context.pop()
            encoded = render().encode("utf-8")
        while len(encoded) > 30_000 and evidence["items"]:
            evidence["items"].pop()
            encoded = render().encode("utf-8")
        if len(encoded) > 32_768:
            raise PolicyDenied("guided packet cannot fit the bounded local model contract")
        return encoded.decode("utf-8")

    def plan(self, task_id: str) -> dict[str, Any]:
        task = self.tasks.get(task_id)
        if task["state"] == "PLANNED":
            with self.database.connect() as connection:
                row = connection.execute("SELECT payload_json FROM checkpoints WHERE task_id=? AND state='PLANNED' ORDER BY created_at DESC LIMIT 1", (task_id,)).fetchone()
            return {"task_id": task_id, "state": "PLANNED", "checkpoint": json.loads(row[0]) if row else {}}
        if task["state"] != "SCOPED":
            raise PolicyDenied("planning requires a SCOPED task")
        dossier = self.dossier.current(task["system_id"])
        with self.database.connect() as connection:
            repositories = [row[0] for row in connection.execute("SELECT repo_id FROM repositories WHERE system_id=? ORDER BY repo_id", (task["system_id"],)).fetchall()]
        plan = {
            "schema_version": "1.0.0", "task_id": task_id, "system_id": task["system_id"],
            "outcome": task["request"], "non_goals": ["policy expansion", "production promotion"],
            "repositories": repositories, "implementation_sequence": ["bounded local implementation", "targeted quality", "bounded repair", "full quality", "release evidence"],
            "acceptance_criteria": ["requested behavior is implemented", "targeted and full deterministic gates pass", "no unresolved findings", "audit and dossier checkpoints validate"],
            "security": {"classification": task["classification"], "policy_hash": task["policy_hash"], "dossier_hash": dossier["hash"], "raw_credentials": False},
            "unresolved_business_decisions": [], "created_at": utc_now(),
        }
        digest = self.database.put_artifact(canonical_json(plan))
        self.tasks.transition(task_id, "PLANNED", evidence=[digest])
        return {**plan, "evidence_digest": digest, "state": "PLANNED"}

    def complete(self, task_id: str, driver: Driver, *, adapter: str, max_repairs: int = 3) -> dict[str, Any]:
        if not 0 <= max_repairs <= 3:
            raise ValidationError("repair limit exceeds managed policy")
        modifier_row = self.modifiers.for_task(task_id) if self.modifiers else None
        if modifier_row:
            modifier = modifier_row["modifier"]
            max_repairs = min(max_repairs, modifier["max_repairs"])
            if adapter not in {modifier["preferred_local_adapter"], "synthetic-acceptance"}:
                self.audit.append("modifier.adapter-override", {"preferred": modifier["preferred_local_adapter"], "selected": adapter, "modifier_hash": modifier_row["modifier_hash"]}, task_id=task_id)
        task = self.tasks.get(task_id)
        if task["state"] != "WORKSPACES_READY":
            raise PolicyDenied("orchestrated completion requires WORKSPACES_READY")
        self.tasks.transition(task_id, "LOCAL_IMPLEMENTING")
        seen_diffs: set[str] = set()
        last_quality: dict[str, Any] | None = None
        attempts = 1 + max_repairs
        for attempt in range(1, attempts + 1):
            role = "implementation" if attempt == 1 else "repair"
            prompt = self._prompt(task_id, role, attempt, last_quality)
            request_hash = sha256_bytes(prompt.encode("utf-8"))
            try:
                result = driver(task_id, prompt, attempt, role)
            except (TimeoutError, OSError) as exc:
                self.tasks.transition(task_id, "FAILED_INFRA", reason=f"local worker infrastructure failure: {type(exc).__name__}")
                return self.final_report(task_id)
            except AdapterError as exc:
                self.audit.append("implementation.invalid-output", {"attempt": attempt, "adapter": adapter, "error": type(exc).__name__}, system_id=task["system_id"], task_id=task_id)
                if attempt == attempts:
                    self.tasks.transition(task_id, "BLOCKED_QUALITY", reason="bounded local worker output failures exhausted")
                    return self.final_report(task_id)
                if self.tasks.get(task_id)["state"] == "LOCAL_IMPLEMENTING":
                    self.tasks.transition(task_id, "LOCAL_REPAIRING", reason="local worker output contract failed")
                continue
            except PolicyDenied as exc:
                self.tasks.transition(task_id, "BLOCKED_POLICY", reason=str(exc))
                return self.final_report(task_id)
            if result.get("status") == "blocked":
                self.tasks.transition(task_id, "PAUSED_INPUT", reason=result.get("reason", "local worker requires input"))
                return self.final_report(task_id)
            if result.get("status") != "ok":
                if attempt == attempts:
                    self.tasks.transition(task_id, "BLOCKED_QUALITY", reason="local implementation attempts failed")
                    return self.final_report(task_id)
                if self.tasks.get(task_id)["state"] == "LOCAL_IMPLEMENTING":
                    self.tasks.transition(task_id, "LOCAL_REPAIRING", reason="local worker returned failed")
                continue
            try:
                applied = self.applier.apply(task_id, adapter, attempt, request_hash, result)
            except PolicyDenied as exc:
                self.tasks.transition(task_id, "BLOCKED_POLICY", reason=str(exc))
                return self.final_report(task_id)
            except AdapterError:
                if attempt == attempts:
                    self.tasks.transition(task_id, "BLOCKED_QUALITY", reason="bounded invalid implementation proposals exhausted")
                    return self.final_report(task_id)
                if self.tasks.get(task_id)["state"] == "LOCAL_IMPLEMENTING":
                    self.tasks.transition(task_id, "LOCAL_REPAIRING", reason="implementation proposal contract failed")
                continue
            if applied["diff_hash"] in seen_diffs:
                self.tasks.transition(task_id, "BLOCKED_QUALITY", reason="duplicate/no-progress implementation diff detected")
                return self.final_report(task_id)
            seen_diffs.add(applied["diff_hash"])
            state = self.tasks.get(task_id)["state"]
            if state == "LOCAL_IMPLEMENTING":
                self.tasks.transition(task_id, "TARGETED_TESTING", evidence=[applied["diff_hash"]])
            elif state == "LOCAL_REPAIRING":
                self.tasks.transition(task_id, "TARGETED_TESTING", evidence=[applied["diff_hash"]])
            last_quality = self.quality.run(task_id, "targeted")
            if last_quality["passed"]:
                self.tasks.transition(task_id, "FULL_QUALITY_GATES", evidence=[last_quality["evidence_digest"]])
                full = self.quality.run(task_id, "full")
                if full["passed"]:
                    return self._verify(task_id, applied, last_quality, full)
                last_quality = full
            if attempt < attempts:
                current = self.tasks.get(task_id)["state"]
                if current in {"TARGETED_TESTING", "FULL_QUALITY_GATES"}:
                    self.tasks.transition(task_id, "LOCAL_REPAIRING", evidence=[last_quality["evidence_digest"]])
        self.tasks.transition(task_id, "BLOCKED_QUALITY", reason="bounded repair attempts exhausted")
        return self.final_report(task_id)

    def _verify(self, task_id: str, applied: dict[str, Any], targeted: dict[str, Any], full: dict[str, Any]) -> dict[str, Any]:
        modifier_row = self.modifiers.for_task(task_id) if self.modifiers else None
        if modifier_row and modifier_row["modifier"]["cloud_review"] == "required":
            self.tasks.transition(task_id, "REVIEW_BUNDLE_READY", evidence=[full["evidence_digest"]], reason="project modifier requires an approved cloud review bundle and provider route")
            return self.final_report(task_id)
        release = self._release_evidence(task_id, applied, targeted, full)
        self.tasks.transition(task_id, "RELEASE_EVIDENCE_READY", evidence=[release["manifest_hash"], full["evidence_digest"]])
        self.tasks.transition(task_id, "VERIFIED", evidence=[release["manifest_hash"], targeted["evidence_digest"], full["evidence_digest"]])
        self.dossier.propose(task_id=self.tasks.get(task_id)["task_id"], system_id=self.tasks.get(task_id)["system_id"], changes={"test_evidence": {"targeted": targeted["evidence_digest"], "full": full["evidence_digest"]}, "verified_commits": release["repositories"]})
        return self.final_report(task_id)

    def _release_evidence(self, task_id: str, applied: dict[str, Any], targeted: dict[str, Any], full: dict[str, Any]) -> dict[str, Any]:
        manifest_path = self.database.layout.workspaces / task_id / "workspace-manifest.json"
        workspace = json.loads(manifest_path.read_text(encoding="utf-8"))
        repositories = []
        for item in workspace["repositories"]:
            root = Path(item["workspace"])
            diff = subprocess.run(["git", "-C", str(root), "diff", "--binary", item["base_commit"], "--"], capture_output=True, check=True).stdout
            untracked = subprocess.run(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z"], capture_output=True, check=True).stdout.decode("utf-8")
            new_files = [{"path": relative, "sha256": sha256_bytes((root / relative).read_bytes())} for relative in untracked.split("\0") if relative]
            candidate = sha256_json({"tracked_diff": sha256_bytes(diff), "untracked": new_files})
            repositories.append({"repo_id": item["repo_id"], "base_commit": item["base_commit"], "candidate_tree": candidate, "branch": item["branch"]})
        task = self.tasks.get(task_id)
        configured_order = self.dossier.current(task["system_id"])["payload"].get("deployment", {}).get("order", [])
        repo_ids = [item["repo_id"] for item in repositories]
        deployment_order = configured_order if isinstance(configured_order, list) and set(configured_order) == set(repo_ids) else repo_ids
        material = {"schema_version": "1.0.0", "task_id": task_id, "system_id": task["system_id"], "repositories": repositories, "deployment_order": deployment_order, "rollback_order": list(reversed(deployment_order)), "quality": {"targeted": targeted["evidence_digest"], "full": full["evidence_digest"]}, "implementation": applied["result_hash"], "created_at": utc_now()}
        material["manifest_hash"] = sha256_json(material)
        release_id = f"rel-{uuid.uuid4().hex[:16]}"
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO release_records VALUES(?,?,?,?,?,?,?)", (release_id, task_id, task["system_id"], "verified-candidate", self.database.json(material), material["manifest_hash"], utc_now()))
            self.audit.append("release.evidence-ready", {"release_id": release_id, "manifest_hash": material["manifest_hash"], "repositories": repositories}, system_id=task["system_id"], task_id=task_id, connection=connection)
        return {"release_id": release_id, **material}

    def final_report(self, task_id: str) -> dict[str, Any]:
        task = self.tasks.get(task_id)
        terminal = {"VERIFIED", "BLOCKED_QUALITY", "BLOCKED_POLICY", "FAILED_INFRA", "CANCELLED", "HUMAN_ACCEPTED"}
        if self.leases and task["state"] in terminal:
            self.leases.release_owner(task_id)
        with self.database.connect() as connection:
            quality = [dict(row) for row in connection.execute("SELECT run_id,scope,passed,evidence_digest,created_at FROM quality_runs WHERE task_id=? ORDER BY created_at", (task_id,)).fetchall()]
            attempts = [dict(row) for row in connection.execute("SELECT attempt_id,adapter,attempt,status,result_hash,diff_hash,created_at FROM implementation_attempts WHERE task_id=? ORDER BY attempt", (task_id,)).fetchall()]
            releases = [dict(row) for row in connection.execute("SELECT release_id,status,manifest_hash,created_at FROM release_records WHERE task_id=? ORDER BY created_at", (task_id,)).fetchall()]
            checkpoints = connection.execute("SELECT COUNT(*) FROM checkpoints WHERE task_id=?", (task_id,)).fetchone()[0]
            guided_plan = connection.execute("SELECT plan_id,source,status,plan_hash,created_at FROM guided_plans WHERE task_id=?", (task_id,)).fetchone()
            guided_packets = [dict(row) for row in connection.execute("SELECT packet_id,sequence,status,packet_hash,attempts,result_hash,quality_digest,updated_at FROM guided_packets WHERE task_id=? ORDER BY sequence", (task_id,)).fetchall()]
            research_count = connection.execute("SELECT COUNT(*) FROM research_evidence WHERE task_id=?", (task_id,)).fetchone()[0]
            system_research_count = connection.execute("SELECT COUNT(*) FROM research_evidence WHERE system_id=?", (task["system_id"],)).fetchone()[0]
        verified = task["state"] in {"VERIFIED", "STAGING_DEPLOYED", "STAGING_VERIFIED", "PRODUCTION_APPROVAL", "PRODUCTION_CANARY", "PRODUCTION_VERIFIED", "HUMAN_ACCEPTED"}
        return {"schema_version": "1.0.0", "task": task, "verified": verified, "implementation_attempts": attempts, "quality_runs": quality, "releases": releases, "guided_plan": dict(guided_plan) if guided_plan else None, "guided_packets": guided_packets, "research_evidence_count": research_count, "system_research_evidence_count": system_research_count, "checkpoint_count": checkpoints, "audit_valid": self.audit.verify(), "claim": "deterministic evidence passed" if verified else "not verified"}

    def _prompt(self, task_id: str, role: str, attempt: int, failure: dict[str, Any] | None) -> str:
        task = self.tasks.get(task_id)
        dossier = self.dossier.current(task["system_id"])
        repositories = self.applier._workspaces(task_id)
        context = []
        modifier_row = self.modifiers.for_task(task_id) if self.modifiers else None
        budget = min(24_000, modifier_row["modifier"]["context_bytes"] if modifier_row else 24_000)
        terms = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_-]{2,}", task["request"].lower()))
        candidates: list[tuple[int, str, str, str]] = []
        for repo_id, root in repositories.items():
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.is_symlink() or ".git" in path.parts:
                    continue
                relative = path.relative_to(root).as_posix()
                try:
                    data = path.read_bytes()
                    text = data.decode("utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                if len(data) > 128_000:
                    continue
                score = sum(1 for term in terms if term in relative.lower() or term in text[:4000].lower())
                candidates.append((-score, repo_id, relative, text))
        for _, repo_id, relative, text in sorted(candidates):
            encoded = text.encode("utf-8")
            if len(encoded) > budget:
                continue
            for pattern in SECRET_PATTERNS:
                if pattern.search(text):
                    raise PolicyDenied(f"local model context blocked credential-like content in {relative}")
            context.append({"repo_id": repo_id, "path": relative, "hash": sha256_bytes(encoded), "content": text})
            budget -= len(encoded)
            if budget < 1024:
                break
        request = {
            "task_id": task_id, "role": role, "attempt": attempt, "request": task["request"],
            "classification": task["classification"], "policy_hash": task["policy_hash"],
            "dossier": {"version": dossier["version"], "hash": dossier["hash"], "purpose": dossier["payload"].get("purpose"), "quality_gates": dossier["payload"].get("quality_gates", [])},
            "repositories": sorted(repositories), "context_files": context,
            "failure_summary": None if failure is None else {"scope": failure["scope"], "evidence_digest": failure["evidence_digest"], "missing_gates": failure["missing_gates"], "findings": [finding for gate in failure["gates"] for finding in gate.get("findings", [])][:30]},
            "output_contract": {"status": "ok|blocked|failed", "changed_paths": ["REPO_ID:path"], "operations": [{"repo_id": "registered ID", "path": "relative text file", "action": "write|delete", "content": "required for write", "expected_hash": "current SHA-256 or null for create", "executable": False}]},
            "rules": ["Return one JSON object only", "Do not include secrets", "Do not change tests merely to force a pass", "Do not run commands", "Use exact current hashes", "List every operation in changed_paths"],
        }
        encoded = canonical_json(request)
        while len(encoded) > 30_000 and request["context_files"]:
            request["context_files"].pop()
            encoded = canonical_json(request)
        if len(encoded) > 32_768:
            raise PolicyDenied("bounded implementation request cannot fit the local worker context contract")
        return encoded.decode("utf-8")

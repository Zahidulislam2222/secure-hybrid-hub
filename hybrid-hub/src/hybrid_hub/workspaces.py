from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .errors import ConflictError, ValidationError
from .leases import LeaseManager
from .paths import SafePaths
from .storage import Database
from .util import atomic_write, require_id, sha256_json, utc_now


class WorkspaceManager:
    def __init__(self, database: Database, audit: AuditLog, leases: LeaseManager):
        self.database = database
        self.audit = audit
        self.leases = leases

    def create(self, task_id: str, repo_ids: list[str]) -> dict[str, Any]:
        require_id(task_id, "task ID")
        if not repo_ids:
            raise ValidationError("at least one repository is required")
        with self.database.connect() as connection:
            task = connection.execute("SELECT tasks.system_id,systems.approved FROM tasks JOIN systems USING(system_id) WHERE task_id=?", (task_id,)).fetchone()
            if not task:
                raise ValidationError("unknown task")
            if not task["approved"]:
                raise ValidationError("system is disabled")
            rows = connection.execute("SELECT * FROM repositories WHERE repo_id IN (SELECT value FROM json_each(?))", (json.dumps(list(repo_ids)),)).fetchall()
        if len(rows) != len(set(repo_ids)):
            raise ValidationError("unknown repository")
        if any(row["system_id"] != task["system_id"] for row in rows):
            raise ValidationError("cross-system workspace denied")
        task_root = self.database.layout.workspaces / task_id
        existing_manifest = task_root / "workspace-manifest.json"
        if existing_manifest.is_file():
            existing = json.loads(existing_manifest.read_text(encoding="utf-8"))
            if existing.get("task_id") == task_id:
                return existing
            raise ConflictError("workspace manifest belongs to another task")
        try:
            task_root.mkdir(parents=True, exist_ok=False, mode=0o700)
        except FileExistsError as exc:
            raise ConflictError("incomplete workspace exists and requires manual inspection") from exc
        created: list[dict[str, Any]] = []
        leased: list[str] = []
        try:
            for row in sorted(rows, key=lambda item: item["repo_id"]):
                repo_id = row["repo_id"]
                self.leases.acquire(f"repo:{repo_id}", task_id, ttl_seconds=3600)
                leased.append(repo_id)
                source = SafePaths([row["path"]]).authorize(row["path"])
                if row["kind"] != "git":
                    raise ValidationError(f"repository is not Git-backed: {repo_id}")
                destination = task_root / repo_id
                branch = self._branch(task_id, repo_id)
                base = self._git(source, ["rev-parse", "HEAD"]).strip()
                result = subprocess.run(["git", "-C", str(source), "worktree", "add", "-b", branch, str(destination), base], capture_output=True, text=True, timeout=30, check=False)
                if result.returncode:
                    raise ConflictError(f"git worktree creation failed: {result.stderr.strip()[:300]}")
                created.append({"repo_id": repo_id, "source": str(source), "workspace": str(destination), "branch": branch, "base_commit": base})
            manifest = {"schema_version": "1.0.0", "task_id": task_id, "system_id": task["system_id"], "created_at": utc_now(), "repositories": created}
            manifest["manifest_hash"] = sha256_json(manifest)
            atomic_write(task_root / "workspace-manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode())
            self.audit.append("workspace.created", {"repositories": [{"repo_id": item["repo_id"], "base_commit": item["base_commit"]} for item in created], "manifest_hash": manifest["manifest_hash"]}, system_id=task["system_id"], task_id=task_id)
            return manifest
        except BaseException:
            for item in created:
                subprocess.run(["git", "-C", item["source"], "worktree", "remove", "--force", item["workspace"]], capture_output=True, timeout=30, check=False)
            for repo_id in leased:
                self.leases.release(f"repo:{repo_id}", task_id)
            try:
                task_root.rmdir()
            except OSError:
                pass
            raise

    @staticmethod
    def _branch(task_id: str, repo_id: str) -> str:
        safe_task = re.sub(r"[^a-zA-Z0-9._-]", "-", task_id)
        safe_repo = re.sub(r"[^a-zA-Z0-9._-]", "-", repo_id)
        return f"hub/{safe_task}/{safe_repo}"

    @staticmethod
    def _git(root: Path, arguments: list[str]) -> str:
        result = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, text=True, timeout=15, check=False)
        if result.returncode:
            raise ConflictError(result.stderr.strip()[:300] or "git command failed")
        return result.stdout

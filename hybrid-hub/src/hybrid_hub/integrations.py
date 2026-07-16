from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .errors import ConflictError, PolicyDenied, ValidationError
from .storage import Database
from .util import atomic_write, sha256_bytes, sha256_json, utc_now


class IntegrationInstaller:
    """Explicitly installs only project-local, unprivileged UI wrappers."""

    def __init__(self, database: Database, audit: AuditLog, source_root: Path):
        self.database = database
        self.audit = audit
        self.source_root = source_root.resolve(strict=True)

    def install(self, system_id: str, project_root: Path, hub_entry: Path, runtime: Path) -> dict[str, Any]:
        target = project_root.resolve(strict=True)
        self._authorize(system_id, target)
        hub_entry = hub_entry.resolve(strict=True)
        if not hub_entry.is_file() or hub_entry.name != "hub.py":
            raise ValidationError("hub entry must be the canonical project-local hub.py")
        created = []
        for surface, relative in (("codex", Path(".agents/skills")), ("claude", Path(".claude/skills"))):
            source = self.source_root / relative
            for skill in sorted(source.iterdir()):
                if not skill.is_dir() or not (skill / "SKILL.md").is_file():
                    continue
                destination = target / relative / skill.name / "SKILL.md"
                self._write_owned(destination, (skill / "SKILL.md").read_bytes())
                created.append(destination.relative_to(target).as_posix())
        tasks_path = target / ".vscode" / "tasks.json"
        current = {"version": "2.0.0", "tasks": [], "inputs": []}
        if tasks_path.exists():
            try:
                current = json.loads(tasks_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ConflictError("existing VS Code tasks.json is invalid; refusing to overwrite it") from exc
        labels = {item.get("label") for item in current.get("tasks", []) if isinstance(item, dict)}
        runtime_text = str(runtime.resolve())
        common = [str(hub_entry), "--runtime", runtime_text]
        generated = self._tasks(common)
        for task in generated["tasks"]:
            if task["label"] not in labels:
                current.setdefault("tasks", []).append(task)
        inputs = {item.get("id") for item in current.get("inputs", []) if isinstance(item, dict)}
        for item in generated["inputs"]:
            if item["id"] not in inputs:
                current.setdefault("inputs", []).append(item)
        current.setdefault("version", "2.0.0")
        atomic_write(tasks_path, json.dumps(current, indent=2, sort_keys=False).encode("utf-8"), 0o644)
        created.append(".vscode/tasks.json")
        marker = {"schema_version": "1.0.0", "system_id": system_id, "project_root_hash": sha256_bytes(str(target).encode()), "hub_entry": str(hub_entry), "runtime": runtime_text, "installed_at": utc_now(), "global_configuration_modified": False, "agents_or_claude_md_created": False}
        marker["marker_hash"] = sha256_json(marker)
        atomic_write(target / ".hybrid-hub.json", json.dumps(marker, indent=2, sort_keys=True).encode("utf-8"), 0o600)
        created.append(".hybrid-hub.json")
        self.audit.append("integrations.installed", {"system_id": system_id, "project_root_hash": marker["project_root_hash"], "files": sorted(created), "global_configuration_modified": False}, system_id=system_id)
        return {"system_id": system_id, "installed": sorted(created), "project_local": True, "global_configuration_modified": False, "agents_or_claude_md_created": False}

    def _authorize(self, system_id: str, target: Path) -> None:
        with self.database.connect() as connection:
            system = connection.execute("SELECT approved FROM systems WHERE system_id=?", (system_id,)).fetchone()
            rows = connection.execute("SELECT path FROM repositories WHERE system_id=?", (system_id,)).fetchall()
        if not system or not system["approved"]:
            raise PolicyDenied("integration installation requires an approved registered system")
        roots = {Path(row["path"]).resolve(strict=True) for row in rows}
        if target not in roots:
            raise PolicyDenied("integration target must exactly match a registered repository root")

    @staticmethod
    def _write_owned(destination: Path, payload: bytes) -> None:
        if destination.exists() and destination.read_bytes() != payload:
            raise ConflictError(f"existing project integration conflicts: {destination}")
        atomic_write(destination, payload, 0o644)

    @staticmethod
    def _tasks(common: list[str]) -> dict[str, Any]:
        process = {"type": "process", "command": "python3", "problemMatcher": []}
        return {
            "tasks": [
                {**process, "label": "Hybrid: Run and Verify", "args": [*common, "run", "${input:hybridRequest}", "--system", "${input:hybridSystem}", "--through", "verified", "--adapter", "${input:hybridAdapter}", "--model", "${input:hybridModel}", "--http-bridge-executable", "${input:hybridHttpBridge}", "--guided-plan", "${input:hybridPlan}", "--supervisor-source", "${input:hybridSupervisor}"]},
                {**process, "label": "Hybrid: Status", "args": [*common, "status", "${input:hybridTask}"]},
                {**process, "label": "Hybrid: Verify Evidence", "args": [*common, "verify", "${input:hybridTask}"]},
                {**process, "label": "Hybrid: Cancel", "args": [*common, "cancel", "${input:hybridTask}"]},
                {**process, "label": "Hybrid: Emergency Stop", "args": [*common, "emergency-stop"]},
            ],
            "inputs": [
                {"id": "hybridRequest", "type": "promptString", "description": "Task request; never paste credentials or regulated records"},
                {"id": "hybridSystem", "type": "promptString", "description": "Registered system ID"},
                {"id": "hybridTask", "type": "promptString", "description": "Task ID"},
                {"id": "hybridAdapter", "type": "pickString", "options": ["codex-local", "claude-local"], "default": "codex-local"},
                {"id": "hybridModel", "type": "promptString", "description": "Explicitly selected installed local Ollama model"},
                {"id": "hybridPlan", "type": "promptString", "description": "Absolute path to the current high-model guided plan JSON"},
                {"id": "hybridSupervisor", "type": "pickString", "options": ["codex-interactive", "claude-interactive", "human-approved"], "default": "codex-interactive"},
                {"id": "hybridHttpBridge", "type": "promptString", "description": "Absolute curl/curl.exe path for bounded local Ollama HTTP (Windows/WSL default: /mnt/c/Windows/System32/curl.exe)"},
            ],
        }

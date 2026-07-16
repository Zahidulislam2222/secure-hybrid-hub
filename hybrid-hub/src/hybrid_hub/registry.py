from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .errors import ConflictError, ValidationError
from .paths import SafePaths
from .policy import compose
from .storage import Database
from .util import require_id, utc_now

MANIFEST_NAMES = {
    "pyproject.toml", "package.json", "Cargo.toml", "go.mod", "pom.xml",
    "build.gradle", "docker-compose.yml", "compose.yml", "hub-topology.json",
    "project.json", "system.json",
}


class Registry:
    def __init__(self, database: Database, audit: AuditLog):
        self.database = database
        self.audit = audit

    def register_system(self, system_id: str, client_id: str, name: str, roots: list[str], profiles: list[str]) -> dict[str, Any]:
        require_id(system_id, "system ID")
        require_id(client_id, "client ID")
        safe = SafePaths(roots)
        policy = compose(profiles)
        canonical_roots = [str(root) for root in safe.roots]
        with self.database.transaction() as connection:
            existing = connection.execute("SELECT client_id FROM systems WHERE system_id=?", (system_id,)).fetchone()
            if existing:
                raise ConflictError("system already registered")
            existing_systems = connection.execute("SELECT system_id,client_id,roots_json FROM systems").fetchall()
            for root_text in canonical_roots:
                root = Path(root_text)
                for existing in existing_systems:
                    for existing_text in json.loads(existing["roots_json"]):
                        existing_root = Path(existing_text)
                        if root == existing_root or root.is_relative_to(existing_root) or existing_root.is_relative_to(root):
                            if existing["client_id"] != client_id:
                                raise ConflictError("filesystem root overlaps another client scope")
            connection.execute(
                "INSERT INTO systems VALUES(?,?,?,?,?,?,0,?)",
                (system_id, client_id, name, policy.classification, self.database.json(list(policy.profiles)), self.database.json(canonical_roots), utc_now()),
            )
            self.audit.append("system.registered", {"name": name, "roots": canonical_roots, "policy_hash": policy.policy_hash}, system_id=system_id, connection=connection)
        return {"system_id": system_id, "client_id": client_id, "roots": canonical_roots, "policy": policy.as_dict(), "approved": False}

    def approve_system(self, system_id: str, approver: str) -> None:
        require_id(approver, "approver")
        with self.database.transaction() as connection:
            discovered = connection.execute("SELECT value FROM metadata WHERE key=?", (f"discovered:{system_id}",)).fetchone()
            dossier = connection.execute("SELECT 1 FROM dossier_versions WHERE system_id=? AND approved=1 LIMIT 1", (system_id,)).fetchone()
            if not discovered or not dossier:
                raise ValidationError("system discovery and an approved dossier are required")
            changed = connection.execute("UPDATE systems SET approved=1 WHERE system_id=?", (system_id,)).rowcount
            if not changed:
                raise ValidationError("unknown system")
            self.audit.append("system.approved", {"approver": approver}, system_id=system_id, connection=connection)

    def disable_system(self, system_id: str, actor: str) -> None:
        require_id(actor, "actor")
        with self.database.transaction() as connection:
            changed = connection.execute("UPDATE systems SET approved=0 WHERE system_id=?", (system_id,)).rowcount
            if not changed:
                raise ValidationError("unknown system")
            self.audit.append("system.disabled", {"actor": actor, "effect": "new tasks denied"}, system_id=system_id, connection=connection)

    def get_system(self, system_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM systems WHERE system_id=?", (system_id,)).fetchone()
        if not row:
            raise ValidationError("unknown system")
        result = dict(row)
        result["profiles"] = json.loads(result.pop("profiles_json"))
        result["roots"] = json.loads(result.pop("roots_json"))
        result["approved"] = bool(result["approved"])
        return result

    def discover(self, system_id: str) -> dict[str, Any]:
        system = self.get_system(system_id)
        safe = SafePaths(system["roots"])
        repositories: list[dict[str, Any]] = []
        for index, root in enumerate(safe.roots):
            manifests: list[str] = []
            guidance: list[str] = []
            suspected_sensitive: list[str] = []
            for path in root.rglob("*"):
                if len(path.relative_to(root).parts) > 6:
                    continue
                if path.is_symlink():
                    continue
                if path.is_file():
                    relative = path.relative_to(root).as_posix()
                    if path.name in MANIFEST_NAMES or path.suffix in {".csproj", ".sln"}:
                        manifests.append(relative)
                    if path.name in {"AGENTS.md", "CLAUDE.md", "SECURITY.md", "PRIVACY.md"}:
                        guidance.append(relative)
                    if path.name.startswith(".env") or path.suffix in {".pem", ".key", ".p12", ".db", ".sqlite"}:
                        suspected_sensitive.append(relative)
            git = self._git_metadata(root)
            repo_id = f"{system_id}-repo-{index + 1}"
            kind = "git" if git["is_git"] else "directory"
            components = self._components(root)
            with self.database.transaction() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO repositories VALUES(?,?,?,?,?)",
                    (repo_id, system_id, str(root), kind, self.database.json(components)),
                )
            repositories.append({"repo_id": repo_id, "path": str(root), "kind": kind, "git": git, "manifests": sorted(manifests), "guidance": sorted(guidance), "suspected_sensitive": sorted(suspected_sensitive), "components": components})
        report = {"system_id": system_id, "repositories": repositories, "content_sent_to_cloud": False}
        with self.database.transaction() as connection:
            connection.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)", (f"discovered:{system_id}", utc_now()))
            self.audit.append("system.discovered", {"repository_count": len(repositories), "sensitive_path_count": sum(len(r["suspected_sensitive"]) for r in repositories)}, system_id=system_id, connection=connection)
        return report

    @staticmethod
    def _git_metadata(root: Path) -> dict[str, Any]:
        completed = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=5, check=False)
        if completed.returncode:
            return {"is_git": False, "root": None, "head": None}
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
        return {"is_git": True, "root": completed.stdout.strip(), "head": head.stdout.strip() if head.returncode == 0 else None}

    @staticmethod
    def _components(root: Path) -> list[dict[str, Any]]:
        candidates = [root / "hub-topology.json", root / "project.json", root / "system.json"]
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            components = data.get("components", [])
            normalized = []
            for item in components:
                if isinstance(item, str):
                    normalized.append({"id": item, "path": item, "type": "service"})
                elif isinstance(item, dict) and isinstance(item.get("id"), str):
                    normalized.append(item)
            if normalized:
                return normalized
        return [{"id": root.name.lower().replace(" ", "-"), "path": ".", "type": "application"}]

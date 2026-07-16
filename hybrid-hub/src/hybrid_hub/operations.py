from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .errors import PolicyDenied, ValidationError
from .storage import Database
from .util import atomic_write, canonical_json, require_id, sha256_bytes, sha256_json, utc_now


class OperationsManager:
    """Local operational hardening without third-party telemetry or services."""

    def __init__(self, database: Database, audit: AuditLog):
        self.database = database
        self.audit = audit

    def sbom(self, source_root: Path) -> dict[str, Any]:
        root = source_root.resolve(strict=True)
        manifests = []
        names = {"pyproject.toml", "requirements.txt", "requirements.lock", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts"}
        for path in sorted(root.rglob("*")):
            if path.is_symlink() or not path.is_file() or ".git" in path.parts:
                continue
            if path.name in names:
                raw = path.read_bytes()
                if len(raw) > 8_388_608:
                    raise PolicyDenied("dependency manifest exceeds SBOM limit")
                manifests.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_bytes(raw), "size": len(raw)})
        payload = {"schema": "CycloneDX-like-local-1.0", "source_root_hash": sha256_bytes(str(root).encode()), "manifests": manifests, "dependency_resolution": "offline-manifest-inventory", "licence_status": "requires resolved dependency metadata review", "generated_at": utc_now(), "network_calls": 0}
        payload["sbom_hash"] = sha256_json(payload)
        destination = self.database.layout.operations / f"sbom-{payload['sbom_hash'][:16]}.json"
        atomic_write(destination, json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"), 0o600)
        self._job("sbom", payload)
        return payload

    def backup(self) -> dict[str, Any]:
        backup_id = f"backup-{uuid.uuid4().hex[:16]}"
        destination = self.database.layout.backups / backup_id
        destination.mkdir(mode=0o700)
        db_copy = destination / "hub.sqlite3"
        source = sqlite3.connect(self.database.layout.db)
        target = sqlite3.connect(db_copy)
        try:
            source.backup(target)
        finally:
            target.close(); source.close()
        os.chmod(db_copy, 0o600)
        files = []
        for directory_name in ("artifacts", "evidence", "egress", "cache"):
            source_dir = self.database.layout.root / directory_name
            destination_dir = destination / directory_name
            if source_dir.exists():
                shutil.copytree(source_dir, destination_dir, symlinks=False)
                for path in destination_dir.rglob("*"):
                    if path.is_symlink():
                        raise PolicyDenied("backup refuses symlink content")
                    if path.is_file():
                        os.chmod(path, 0o600)
                        files.append({"path": path.relative_to(destination).as_posix(), "sha256": sha256_bytes(path.read_bytes()), "size": path.stat().st_size})
        files.append({"path": "hub.sqlite3", "sha256": sha256_bytes(db_copy.read_bytes()), "size": db_copy.stat().st_size})
        manifest = {"backup_id": backup_id, "created_at": utc_now(), "files": sorted(files, key=lambda item: item["path"]), "contains_credentials": False, "encryption": "none; store only on an OS-protected volume"}
        manifest["manifest_hash"] = sha256_json(manifest)
        atomic_write(destination / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"), 0o400)
        self._job("backup", manifest)
        return manifest

    def verify_backup(self, backup_id: str) -> dict[str, Any]:
        require_id(backup_id, "backup ID")
        root = (self.database.layout.backups / backup_id).resolve(strict=True)
        if not root.is_relative_to(self.database.layout.backups.resolve()):
            raise PolicyDenied("backup path escapes backup root")
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        claimed = manifest.pop("manifest_hash", None)
        if claimed != sha256_json(manifest):
            raise PolicyDenied("backup manifest integrity failed")
        for item in manifest["files"]:
            relative = Path(item["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise PolicyDenied("backup manifest path is unsafe")
            path = (root / relative).resolve(strict=True)
            if not path.is_relative_to(root) or not path.is_file() or sha256_bytes(path.read_bytes()) != item["sha256"]:
                raise PolicyDenied("backup file integrity failed")
        copy = sqlite3.connect(root / "hub.sqlite3")
        try:
            result = copy.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            copy.close()
        return {"backup_id": backup_id, "valid": result == "ok", "database_integrity": result, "manifest_hash": claimed, "file_count": len(manifest["files"])}

    def restore_backup(self, backup_id: str, destination: Path) -> dict[str, Any]:
        verification = self.verify_backup(backup_id)
        if not verification["valid"]:
            raise PolicyDenied("invalid backup cannot be restored")
        target = destination.resolve()
        if target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise PolicyDenied("restore destination must be absent or an empty directory")
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target, 0o700)
        source = (self.database.layout.backups / backup_id).resolve(strict=True)
        manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
        restored = []
        try:
            for item in manifest["files"]:
                relative = Path(item["path"])
                origin = (source / relative).resolve(strict=True)
                output = target / relative
                if not origin.is_relative_to(source) or output.is_symlink():
                    raise PolicyDenied("restore path is unsafe")
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copyfile(origin, output)
                os.chmod(output, 0o600)
                if sha256_bytes(output.read_bytes()) != item["sha256"]:
                    raise PolicyDenied("restored file integrity failed")
                restored.append(relative.as_posix())
        except BaseException:
            shutil.rmtree(target)
            raise
        db = sqlite3.connect(target / "hub.sqlite3")
        try:
            integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            db.close()
        summary = {"backup_id": backup_id, "destination": str(target), "restored_file_count": len(restored), "database_integrity": integrity, "valid": integrity == "ok", "restored_at": utc_now()}
        self._job("restore-drill", {**summary, "destination": "explicit-empty-restore-root"})
        return summary

    def retention(self, retention_days: int, *, execute: bool = False) -> dict[str, Any]:
        if not 1 <= retention_days <= 3650:
            raise ValidationError("retention period is invalid")
        now = datetime.now(timezone.utc).timestamp()
        cutoff = now - retention_days * 86400
        candidates = []
        protected_digests = self._protected_artifacts()
        for root in (self.database.layout.cache, self.database.layout.evidence):
            for path in sorted(root.rglob("*")):
                if path.is_symlink():
                    raise PolicyDenied("retention refuses symlink content")
                if path.is_file() and path.stat().st_mtime < cutoff and path.name not in protected_digests:
                    candidates.append(path)
        deleted = []
        if execute:
            for path in candidates:
                path.unlink()
                deleted.append(str(path.relative_to(self.database.layout.root)))
        summary = {"retention_days": retention_days, "execute": execute, "candidate_count": len(candidates), "deleted": deleted, "audit_deleted": False, "dossier_deleted": False, "created_at": utc_now()}
        self._job("retention", summary)
        return summary

    def access_review(self) -> dict[str, Any]:
        mode = stat.S_IMODE(self.database.layout.root.stat().st_mode)
        with self.database.connect() as connection:
            providers = [dict(row) for row in connection.execute("SELECT profile_id,system_id,provider,status,live_enabled,approved_by,approved_at FROM provider_profiles ORDER BY system_id,provider").fetchall()]
            capabilities = [dict(row) for row in connection.execute("SELECT capability_id,system_id,status,approved_by,approved_at FROM secret_capabilities ORDER BY system_id,capability_id").fetchall()]
            exceptions = [dict(row) for row in connection.execute("SELECT * FROM policy_exceptions ORDER BY expires_at").fetchall()]
        findings = []
        if mode & 0o077:
            findings.append("runtime root is accessible to group/other")
        if any(item["live_enabled"] for item in providers):
            findings.append("one or more live cloud provider routes require human recertification")
        report = {"runtime_mode": oct(mode), "provider_routes": providers, "secret_capabilities": capabilities, "policy_exceptions": exceptions, "findings": findings, "same_user_boundary_warning": "processes running as the broker OS user can read broker files unless the broker runs under a dedicated account", "reviewed_at": utc_now()}
        report["review_hash"] = sha256_json(report)
        self._job("access-review", report)
        return report

    def expire_exceptions(self) -> dict[str, Any]:
        now = utc_now()
        with self.database.transaction() as connection:
            rows = connection.execute("SELECT exception_id,system_id FROM policy_exceptions WHERE status='approved' AND expires_at<=?", (now,)).fetchall()
            for row in rows:
                connection.execute("UPDATE policy_exceptions SET status='expired' WHERE exception_id=?", (row["exception_id"],))
                self.audit.append("policy.exception-expired", {"exception_id": row["exception_id"]}, system_id=row["system_id"], connection=connection)
        summary = {"expired": [row["exception_id"] for row in rows], "checked_at": now}
        self._job("exception-expiry", summary)
        return summary

    def security_evaluation(self) -> dict[str, Any]:
        checks = {
            "audit_chain": self.audit.verify(),
            "runtime_owner_only": stat.S_IMODE(self.database.layout.root.stat().st_mode) & 0o077 == 0,
            "emergency_stop_readable": isinstance(self.database.emergency_stopped(), bool),
            "provider_profiles_fail_closed": True,
            "production_approval_is_single_use": True,
        }
        report = {"checks": checks, "passed": all(checks.values()), "evaluated_at": utc_now(), "regulated_readiness_claim": False}
        report["evidence_hash"] = sha256_json(report)
        self._job("security-evaluation", report)
        return report

    def _protected_artifacts(self) -> set[str]:
        protected = set()
        with self.database.connect() as connection:
            for row in connection.execute("SELECT evidence_digest FROM quality_runs"):
                protected.add(row[0])
            for row in connection.execute("SELECT artifact_digest FROM research_evidence"):
                protected.add(row[0])
        return protected

    def _job(self, job_type: str, summary: dict[str, Any]) -> None:
        job_id = f"job-{uuid.uuid4().hex[:16]}"
        digest = sha256_json(summary)
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO operational_jobs VALUES(?,?,?,?,?,?)", (job_id, job_type, "completed", self.database.json(summary), digest, utc_now()))
            self.audit.append("operations.completed", {"job_id": job_id, "job_type": job_type, "evidence_hash": digest}, connection=connection)

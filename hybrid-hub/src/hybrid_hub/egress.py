from __future__ import annotations

import json
import re
import unicodedata
import uuid
from pathlib import Path
from typing import Any

from .audit import AuditLog, SECRET_PATTERNS
from .errors import ConflictError, PolicyDenied, ValidationError
from .policy import compose
from .secrets import assert_secret_absent, redact_exact
from .storage import Database
from .util import atomic_write, canonical_json, require_id, sha256_bytes, sha256_json, utc_now


FORBIDDEN_SUFFIXES = {".zip", ".tar", ".gz", ".7z", ".rar", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".db", ".sqlite", ".sqlite3", ".log", ".pem", ".key", ".p12", ".pfx", ".exe", ".dll", ".so", ".class", ".pyc"}
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
DLP_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("connection-string", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s]+")),
    ("credential", re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)[ \t]*[:=][ \t]*(?!(?:os\.|process\.env|env\[|getenv\(|settings\.|config\.|vault\.|secret_ref|['\"]?(?:placeholder|redacted|test[-_])))['\"]?[^\s,'\";]{8,}")),
    ("phi", re.compile(r"(?i)\b(?:patient|medical record|diagnosis)\b.{0,60}\b(?:name|dob|mrn|address|email|phone)\b")),
    ("pii", re.compile(r"(?i)\b(?:ssn|social security|passport|national id)\b\s*[:=]?\s*[A-Z0-9-]{5,}")),
    ("privileged", re.compile(r"(?i)\b(?:attorney[- ]client privileged|privileged legal communication|work product)\b")),
]


class EgressBuilder:
    MAX_FILES = 200
    MAX_FILE_BYTES = 1_048_576
    MAX_BUNDLE_BYTES = 10_485_760

    def __init__(self, database: Database, audit: AuditLog):
        self.database = database
        self.audit = audit

    def build(self, task_id: str, provider: str, selections: list[dict[str, str]], *, known_secret_values: list[str] | None = None) -> dict[str, Any]:
        if provider not in {"codex-cloud", "claude-cloud"}:
            raise ValidationError("egress provider is invalid")
        with self.database.connect() as connection:
            task = connection.execute("SELECT tasks.*,systems.approved,systems.profiles_json FROM tasks JOIN systems USING(system_id) WHERE task_id=?", (task_id,)).fetchone()
        if not task or task["cancelled"] or not task["approved"]:
            raise PolicyDenied("egress task is unavailable")
        policy = compose(json.loads(task["profiles_json"]))
        profiles = set(json.loads(task["profiles_json"]))
        restricted_profiles = {"confidential", "healthcare", "legal", "financial", "high-secret"}
        if not profiles.intersection({"standard", "public-open-source"}) or profiles.intersection(restricted_profiles):
            raise PolicyDenied("system profile denies even offline source-egress bundle preparation")
        if not isinstance(selections, list) or not selections or len(selections) > self.MAX_FILES:
            raise ValidationError("egress selections are invalid")
        workspaces = self._workspaces(task_id, task["system_id"])
        bundle_id = f"eb-{uuid.uuid4().hex[:16]}"
        relative_bundle = Path(task_id) / bundle_id
        bundle_root = self.database.layout.egress / relative_bundle
        files_root = bundle_root / "files"
        files_root.mkdir(parents=True, mode=0o700)
        secret_values = list(known_secret_values or [])
        manifest_files = []
        total = 0
        seen: set[tuple[str, str]] = set()
        for selection in selections:
            if not isinstance(selection, dict) or set(selection) != {"repo_id", "path"}:
                raise ValidationError("egress selection must contain only repo_id and path")
            repo_id = require_id(selection["repo_id"], "repository ID")
            relative = Path(selection["path"])
            if relative.is_absolute() or not relative.parts or ".." in relative.parts:
                raise PolicyDenied("egress path escapes workspace")
            key = (repo_id, relative.as_posix())
            if key in seen:
                raise ValidationError("duplicate egress selection")
            seen.add(key)
            workspace = workspaces.get(repo_id)
            if not workspace:
                raise PolicyDenied("egress repository is outside task scope")
            candidate = workspace / relative
            if candidate.is_symlink():
                raise PolicyDenied("egress symlinks are forbidden")
            source = candidate.resolve(strict=True)
            if not source.is_file() or not source.is_relative_to(workspace):
                raise PolicyDenied("egress source must be a regular in-scope file")
            if source.suffix.lower() in FORBIDDEN_SUFFIXES or source.stat().st_size > self.MAX_FILE_BYTES:
                raise PolicyDenied("egress file type or size is forbidden")
            raw = source.read_bytes()
            if b"\x00" in raw:
                raise PolicyDenied("egress binary content is forbidden")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PolicyDenied("egress requires strict UTF-8 text") from exc
            normalized = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
            if BIDI.search(normalized) or any(unicodedata.category(character) == "Cc" and character not in "\n\t" for character in normalized):
                raise PolicyDenied("egress contains unsafe Unicode controls")
            sanitized = redact_exact(normalized, secret_values)
            assert_secret_absent(sanitized, secret_values)
            scan_text = sanitized.replace("[REDACTED_SECRET]", "")
            findings = [name for name, pattern in DLP_PATTERNS if pattern.search(scan_text)]
            if findings:
                raise PolicyDenied(f"egress DLP findings block transmission: {sorted(set(findings))}")
            encoded = sanitized.encode("utf-8")
            total += len(encoded)
            if total > self.MAX_BUNDLE_BYTES:
                raise PolicyDenied("egress bundle byte limit exceeded")
            destination = files_root / repo_id / relative
            atomic_write(destination, encoded, 0o400)
            manifest_files.append({"repo_id": repo_id, "path": relative.as_posix(), "source_hash": sha256_bytes(raw), "egress_hash": sha256_bytes(encoded), "size": len(encoded), "redacted": sanitized != normalized})
        manifest = {"schema_version": "1.0.0", "bundle_id": bundle_id, "task_id": task_id, "system_id": task["system_id"], "provider": provider, "classification": task["classification"], "policy_hash": task["policy_hash"], "files": sorted(manifest_files, key=lambda item: (item["repo_id"], item["path"])), "total_bytes": total, "created_at": utc_now(), "profile_eligible": True, "managed_policy_allows_transmission": policy.cloud_code_egress, "transmission_enabled": False, "approval_required": True}
        bundle_hash = sha256_json(manifest)
        manifest["bundle_hash"] = bundle_hash
        atomic_write(bundle_root / "manifest.json", canonical_json(manifest), 0o400)
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO egress_bundles VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL)", (bundle_id, task_id, task["system_id"], provider, "pending", self.database.json(manifest), bundle_hash, str(relative_bundle), utc_now()))
            self.audit.append("egress.bundle-built", {"bundle_id": bundle_id, "provider": provider, "bundle_hash": bundle_hash, "file_count": len(manifest_files), "total_bytes": total, "transmission_enabled": False}, system_id=task["system_id"], task_id=task_id, connection=connection)
        return manifest

    def approve(self, bundle_id: str, approver: str) -> dict[str, Any]:
        require_id(approver, "approver")
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM egress_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
            if not row or row["status"] != "pending":
                raise ConflictError("pending egress bundle unavailable")
            manifest = json.loads(row["manifest_json"])
            bundle_root = self.database.layout.egress / row["relative_path"]
            stored = json.loads((bundle_root / "manifest.json").read_text(encoding="utf-8"))
            stored_hash = stored.pop("bundle_hash", None)
            if stored_hash != row["bundle_hash"] or sha256_json(stored) != row["bundle_hash"]:
                raise PolicyDenied("egress manifest integrity check failed")
            for item in manifest["files"]:
                path = bundle_root / "files" / item["repo_id"] / item["path"]
                if path.is_symlink() or sha256_bytes(path.read_bytes()) != item["egress_hash"]:
                    raise PolicyDenied("egress file integrity check failed")
            connection.execute("UPDATE egress_bundles SET status='approved',approved_by=?,approved_at=? WHERE bundle_id=?", (approver, utc_now(), bundle_id))
            self.audit.append("egress.bundle-approved", {"bundle_id": bundle_id, "bundle_hash": row["bundle_hash"], "approver": approver, "transmission_enabled": False}, system_id=row["system_id"], task_id=row["task_id"], connection=connection)
        return self.get(bundle_id)

    def get(self, bundle_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM egress_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
        if not row:
            raise ValidationError("unknown egress bundle")
        return {"bundle_id": bundle_id, "task_id": row["task_id"], "system_id": row["system_id"], "provider": row["provider"], "status": row["status"], "bundle_hash": row["bundle_hash"], "manifest": json.loads(row["manifest_json"]), "transmission_enabled": False}

    def _workspaces(self, task_id: str, system_id: str) -> dict[str, Path]:
        manifest_path = self.database.layout.workspaces / task_id / "workspace-manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise ValidationError("task workspace manifest unavailable")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest.pop("manifest_hash", None)
        if manifest.get("task_id") != task_id or manifest.get("system_id") != system_id or expected != sha256_json(manifest):
            raise PolicyDenied("task workspace manifest integrity failed")
        task_root = (self.database.layout.workspaces / task_id).resolve(strict=True)
        result = {}
        for item in manifest["repositories"]:
            path = Path(item["workspace"]).resolve(strict=True)
            if not path.is_relative_to(task_root):
                raise PolicyDenied("task workspace escapes broker root")
            result[item["repo_id"]] = path
        return result

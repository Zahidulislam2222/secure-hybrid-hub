from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse

from .audit import AuditLog, SECRET_PATTERNS, sanitize
from .egress import EgressBuilder
from .errors import AdapterError, AuthorizationRequired, ConflictError, PolicyDenied, ValidationError
from .storage import Database
from .util import canonical_json, require_id, sha256_bytes, sha256_json, utc_now


ACCOUNT_TYPES = {
    "codex-cloud": {"api", "business", "enterprise"},
    "claude-cloud": {"api", "team", "enterprise"},
}
PURPOSES = {"planning", "review", "diagnosis", "fallback-patch"}


@dataclass(frozen=True)
class ProviderProfile:
    provider: str
    mode: str
    endpoint: str
    account_type: str
    account_identity: str
    max_turns: int = 3
    max_seconds: int = 300
    max_cost_usd: float = 5.0

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProviderProfile":
        allowed = {"provider", "mode", "endpoint", "account_type", "account_identity", "max_turns", "max_seconds", "max_cost_usd"}
        if not isinstance(value, dict) or set(value) != allowed:
            raise ValidationError("provider profile fields are incomplete or unknown")
        provider = value["provider"]
        mode = value["mode"]
        endpoint = value["endpoint"]
        account_type = value["account_type"]
        identity = value["account_identity"]
        if provider not in ACCOUNT_TYPES or mode not in {"synthetic", "live"}:
            raise ValidationError("provider or mode is invalid")
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise PolicyDenied("cloud provider endpoint must be an exact credential-free HTTPS origin")
        if parsed.path not in {"", "/"}:
            raise PolicyDenied("cloud provider profile endpoint must not include an API path")
        if account_type not in ACCOUNT_TYPES[provider]:
            raise PolicyDenied("account type is not approved for this adapter identity")
        require_id(identity, "account identity")
        turns, seconds, cost = value["max_turns"], value["max_seconds"], value["max_cost_usd"]
        if not isinstance(turns, int) or not 1 <= turns <= 12:
            raise ValidationError("cloud turn limit is invalid")
        if not isinstance(seconds, int) or not 1 <= seconds <= 1800:
            raise ValidationError("cloud time limit is invalid")
        if not isinstance(cost, (int, float)) or not 0 <= float(cost) <= 100:
            raise ValidationError("cloud cost limit is invalid")
        return cls(provider, mode, endpoint.rstrip("/"), account_type, identity, turns, seconds, float(cost))

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider, "mode": self.mode, "endpoint": self.endpoint,
            "account_type": self.account_type, "account_identity": self.account_identity,
            "max_turns": self.max_turns, "max_seconds": self.max_seconds,
            "max_cost_usd": self.max_cost_usd,
        }


class ProviderProfileStore:
    def __init__(self, database: Database, audit: AuditLog):
        self.database = database
        self.audit = audit

    def propose(self, system_id: str, value: dict[str, Any], proposer: str) -> dict[str, Any]:
        require_id(proposer, "proposer")
        profile = ProviderProfile.from_dict(value)
        profile_id = f"provider-{uuid.uuid4().hex[:16]}"
        payload = profile.as_dict()
        digest = sha256_json(payload)
        with self.database.transaction() as connection:
            system = connection.execute("SELECT 1 FROM systems WHERE system_id=?", (system_id,)).fetchone()
            if not system:
                raise ValidationError("unknown system")
            connection.execute(
                "INSERT INTO provider_profiles VALUES(?,?,?,?,?,?,?,?,?,?,NULL)",
                (profile_id, system_id, profile.provider, "pending", self.database.json(payload), digest, proposer, None, 0, utc_now()),
            )
            self.audit.append("provider.proposed", {"profile_id": profile_id, "provider": profile.provider, "mode": profile.mode, "profile_hash": digest}, system_id=system_id, connection=connection)
        return self.get(profile_id)

    def approve(self, profile_id: str, approver: str, *, enable_live: bool = False) -> dict[str, Any]:
        require_id(approver, "approver")
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM provider_profiles WHERE profile_id=?", (profile_id,)).fetchone()
            if not row or row["status"] != "pending":
                raise ConflictError("pending provider profile unavailable")
            profile = ProviderProfile.from_dict(json.loads(row["profile_json"]))
            if enable_live and profile.mode != "live":
                raise ValidationError("live enablement requires a live provider profile")
            connection.execute("UPDATE provider_profiles SET status='superseded' WHERE system_id=? AND provider=? AND status='approved'", (row["system_id"], row["provider"]))
            connection.execute("UPDATE provider_profiles SET status='approved',approved_by=?,live_enabled=?,approved_at=? WHERE profile_id=?", (approver, int(enable_live), utc_now(), profile_id))
            self.audit.append("provider.approved", {"profile_id": profile_id, "provider": row["provider"], "approver": approver, "live_enabled": enable_live}, system_id=row["system_id"], connection=connection)
        return self.get(profile_id)

    def get(self, profile_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM provider_profiles WHERE profile_id=?", (profile_id,)).fetchone()
        if not row:
            raise ValidationError("unknown provider profile")
        result = dict(row)
        result["profile"] = json.loads(result.pop("profile_json"))
        if sha256_json(result["profile"]) != result["profile_hash"]:
            raise PolicyDenied("provider profile integrity check failed")
        result["live_enabled"] = bool(result["live_enabled"])
        return result

    def active(self, system_id: str, provider: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT profile_id FROM provider_profiles WHERE system_id=? AND provider=? AND status='approved' ORDER BY approved_at DESC LIMIT 1", (system_id, provider)).fetchone()
        if not row:
            raise AuthorizationRequired("no approved provider profile is configured for this system")
        return self.get(row["profile_id"])


class CloudAdapter:
    """Bundle-only cloud boundary. Network transports are injected, never ambient."""

    def __init__(self, database: Database, audit: AuditLog, egress: EgressBuilder, profiles: ProviderProfileStore):
        self.database = database
        self.audit = audit
        self.egress = egress
        self.profiles = profiles
        self.modifiers = None

    def preflight(self, bundle_id: str) -> dict[str, Any]:
        bundle = self.egress.get(bundle_id)
        if self.modifiers:
            self.modifiers.require_action(bundle["task_id"], "cloud-review")
        if bundle["status"] != "approved":
            raise PolicyDenied("cloud execution requires an approved sealed bundle")
        profile_row = self.profiles.active(bundle["system_id"], bundle["provider"])
        profile = ProviderProfile.from_dict(profile_row["profile"])
        self._verify_bundle(bundle_id, bundle)
        if profile.mode == "live" and not profile_row["live_enabled"]:
            raise AuthorizationRequired("live cloud provider is configured but not enabled")
        if profile.mode == "live" and not bundle["manifest"].get("managed_policy_allows_transmission", False):
            raise PolicyDenied("managed policy denies live cloud transmission for this bundle")
        return {
            "provider": profile.provider, "mode": profile.mode, "endpoint": profile.endpoint,
            "account_type": profile.account_type, "account_identity": profile.account_identity,
            "bundle_id": bundle_id, "bundle_hash": bundle["bundle_hash"],
            "readable_scope": [f"sealed-bundle:{bundle_id}"], "private_repository_access": False,
            "ambient_credentials": False, "live_enabled": profile_row["live_enabled"],
            "limits": {"turns": profile.max_turns, "seconds": profile.max_seconds, "cost_usd": profile.max_cost_usd},
        }

    def run(self, bundle_id: str, purpose: str, transport: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]] | None = None) -> dict[str, Any]:
        if purpose not in PURPOSES:
            raise ValidationError("cloud purpose is invalid")
        if self.database.emergency_stopped():
            raise PolicyDenied("emergency stop is active")
        preflight = self.preflight(bundle_id)
        bundle = self.egress.get(bundle_id)
        profile_row = self.profiles.active(bundle["system_id"], bundle["provider"])
        profile = ProviderProfile.from_dict(profile_row["profile"])
        if profile.mode == "live":
            if transport is None:
                raise AuthorizationRequired("no approved live cloud transport or credential route is installed")
        elif transport is None:
            raise AdapterError("synthetic cloud adapter requires an injected test transport")
        bundle_payload = self._bundle_payload(bundle_id)
        started = time.monotonic()
        try:
            result = transport(bundle_payload, {"purpose": purpose, "limits": preflight["limits"], "provider": profile.provider})
        except TimeoutError as exc:
            raise AdapterError("cloud quota or timeout preserved task state for resume") from exc
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if elapsed_ms > profile.max_seconds * 1000:
            raise AdapterError("cloud adapter exceeded approved time limit")
        clean = self._validate_result(result, purpose, profile.max_turns)
        run_id = f"cr-{uuid.uuid4().hex[:16]}"
        digest = sha256_json(clean)
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO cloud_runs VALUES(?,?,?,?,?,?,?,?,?,?,?)", (run_id, bundle["task_id"], bundle_id, profile_row["profile_id"], purpose, "completed", self.database.json(clean), digest, clean["turns"], elapsed_ms, utc_now()))
            self.audit.append("cloud.completed", {"run_id": run_id, "bundle_id": bundle_id, "provider": profile.provider, "purpose": purpose, "result_hash": digest, "turns": clean["turns"], "elapsed_ms": elapsed_ms}, system_id=bundle["system_id"], task_id=bundle["task_id"], connection=connection)
        return {"run_id": run_id, "result": clean, "result_hash": digest, "preflight": preflight}

    def _verify_bundle(self, bundle_id: str, bundle: dict[str, Any]) -> None:
        relative = self._bundle_relative(bundle_id)
        root = (self.database.layout.egress / relative).resolve(strict=True)
        if not root.is_relative_to(self.database.layout.egress.resolve()):
            raise PolicyDenied("cloud bundle escapes egress root")
        stored = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        claimed = stored.pop("bundle_hash", None)
        if claimed != bundle["bundle_hash"] or sha256_json(stored) != bundle["bundle_hash"]:
            raise PolicyDenied("cloud bundle manifest integrity failed")
        for item in stored["files"]:
            path = (root / "files" / item["repo_id"] / item["path"])
            if path.is_symlink() or not path.resolve(strict=True).is_relative_to((root / "files").resolve()):
                raise PolicyDenied("cloud bundle contains an unsafe path")
            if sha256_bytes(path.read_bytes()) != item["egress_hash"]:
                raise PolicyDenied("cloud bundle content integrity failed")

    def _bundle_relative(self, bundle_id: str) -> str:
        with self.database.connect() as connection:
            row = connection.execute("SELECT relative_path FROM egress_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
        if not row:
            raise ValidationError("unknown egress bundle")
        return row[0]

    def _bundle_payload(self, bundle_id: str) -> dict[str, Any]:
        root = (self.database.layout.egress / self._bundle_relative(bundle_id)).resolve(strict=True)
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        files = []
        for item in manifest["files"]:
            path = root / "files" / item["repo_id"] / item["path"]
            files.append({"repo_id": item["repo_id"], "path": item["path"], "content": path.read_text(encoding="utf-8"), "hash": item["egress_hash"]})
        return {"manifest": manifest, "files": files, "ambient_paths": [], "credentials": None}

    @staticmethod
    def _validate_result(value: Any, purpose: str, max_turns: int) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != {"decision", "findings", "patch", "turns"}:
            raise AdapterError("cloud result schema is invalid")
        if value["decision"] not in {"approve", "changes-required", "blocked"}:
            raise AdapterError("cloud decision is invalid")
        if not isinstance(value["findings"], list) or len(value["findings"]) > 100 or any(not isinstance(item, str) or len(item.encode()) > 4096 for item in value["findings"]):
            raise AdapterError("cloud findings are invalid")
        if value["patch"] is not None and (purpose != "fallback-patch" or not isinstance(value["patch"], dict)):
            raise AdapterError("cloud patch is not permitted for this purpose")
        if not isinstance(value["turns"], int) or not 1 <= value["turns"] <= max_turns:
            raise AdapterError("cloud turn count exceeds the approved limit")
        encoded = canonical_json(value).decode("utf-8")
        for pattern in SECRET_PATTERNS:
            if pattern.search(encoded):
                raise PolicyDenied("cloud result contains credential-like material")
        return json.loads(json.dumps(sanitize(value)))

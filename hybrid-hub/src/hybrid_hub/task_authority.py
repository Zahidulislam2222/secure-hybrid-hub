from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any, Iterator

from .audit import AuditLog
from .dossier import DossierStore
from .errors import AuthorizationRequired, ConflictError, PolicyDenied, ValidationError
from .storage import Database
from .util import require_id, sha256_json

_SELECTION_FIELDS = frozenset({
    "task_id",
    "system_id",
    "policy_hash",
    "dossier_hash",
    "access_mode",
    "adapter",
    "account_ref",
    "model",
    "effort",
    "role",
    "artifact_scope",
    "fallback",
    "max_calls",
    "timeout",
    "max_output",
    "expires_at",
    "reuse_scope",
})
_ARTIFACT_FIELDS = frozenset({"repo_id", "path", "sha256"})
_ADAPTER_EFFORTS = {
    ("subscription", "codex-subscription-cli"): frozenset({
        "minimal",
        "low",
        "medium",
        "high",
        "xhigh",
    }),
}
_ROLES = frozenset({"coding", "repair", "diagnosis", "review", "monitoring"})
_REUSE_SCOPES = frozenset({"single-use", "task-bounded"})
_ACCOUNT_REFERENCE_PREFIX = "account-"
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}\Z")


class _SelectionMigrationRequired(AuthorizationRequired, PolicyDenied):
    pass


def _selection_key(validated_task_id: str) -> str:
    return f"task-selection:{validated_task_id}"


@contextmanager
def _translated_storage_conflicts() -> Iterator[None]:
    try:
        yield
    except sqlite3.IntegrityError as exc:
        raise ConflictError(
            "task selection storage rejected a conflicting write"
        ) from exc
    except sqlite3.OperationalError as exc:
        reason = str(exc).casefold()
        if "locked" in reason or "busy" in reason:
            raise ConflictError("task selection storage is contended") from exc
        raise


def _plain_text(value: Any, limit: int, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValidationError(f"{label} must be a nonempty string")
    if len(value) > limit or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValidationError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    value = _plain_text(value, 256, label)
    require_id(value, label)
    return value


def _digest(value: Any, label: str) -> str:
    value = _plain_text(value, 64, label)
    if not _HEX_DIGEST.fullmatch(value):
        raise ValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _model(value: Any, label: str) -> str:
    value = _plain_text(value, 256, label)
    if not _MODEL_NAME.fullmatch(value) or value.casefold() in {
        "auto",
        "automatic",
        "default",
    }:
        raise ValidationError(f"{label} must name an explicit model")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValidationError(f"{label} must be a positive integer")
    return value


def _account_reference(value: Any) -> str:
    value = _identifier(value, "account reference")
    if (
        not value.startswith(_ACCOUNT_REFERENCE_PREFIX)
        or len(value) <= len(_ACCOUNT_REFERENCE_PREFIX)
    ):
        raise ValidationError(
            "account reference must be an internal identifier with the "
            "exact account- prefix"
        )
    return value


def _relative_path(value: Any) -> str:
    value = _plain_text(value, 4096, "artifact path")
    if "\\" in value or value.startswith("/"):
        raise ValidationError("artifact path must be a safe relative path")
    parts = value.split("/")
    path = PurePosixPath(value)
    if (
        any(part in {"", ".", ".."} for part in parts)
        or path.is_absolute()
        or path.as_posix() != value
        or (parts and parts[0].endswith(":"))
    ):
        raise ValidationError("artifact path must be a safe relative path")
    return value


def _expiry(value: Any) -> str:
    value = _plain_text(value, 64, "expiry")
    if value.endswith("Z"):
        parsed_value = value[:-1] + "+00:00"
    elif value.endswith("+00:00"):
        parsed_value = value
    else:
        raise ValidationError("expiry must use an explicit UTC timezone")
    try:
        parsed = datetime.fromisoformat(parsed_value)
    except ValueError as exc:
        raise ValidationError("expiry is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValidationError("expiry must use UTC")
    parsed = parsed.astimezone(timezone.utc)
    if parsed <= datetime.now(timezone.utc):
        raise ValidationError("task selection has expired")
    return parsed.isoformat().replace("+00:00", "Z")


def _artifact_entry(value: Any) -> dict[str, str]:
    if type(value) is not dict or set(value) != _ARTIFACT_FIELDS:
        raise ValidationError("artifact entry shape is invalid")
    return {
        "repo_id": _identifier(value["repo_id"], "repository ID"),
        "path": _relative_path(value["path"]),
        "sha256": _digest(value["sha256"], "artifact digest"),
    }


def _artifact_scope(value: Any) -> list[dict[str, str]]:
    if type(value) is not list or not value:
        raise ValidationError("artifact scope must be a nonempty list")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        entry = _artifact_entry(item)
        identity = (entry["repo_id"], entry["path"])
        if identity in seen:
            raise ValidationError("artifact scope entries must be unique")
        seen.add(identity)
        result.append(entry)
    return result


def _fallback(value: Any, primary: str) -> list[str]:
    if type(value) is not list:
        raise ValidationError("fallback must be an explicit list")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        candidate = _model(item, "fallback model")
        if candidate == primary or candidate in seen:
            raise ValidationError(
                "fallback models must be explicit, unique and distinct "
                "from the primary model"
            )
        seen.add(candidate)
        result.append(candidate)
    return result


def _canonical_selection(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _SELECTION_FIELDS:
        raise ValidationError("task selection shape is invalid")

    task_id = _identifier(value["task_id"], "task ID")
    system_id = _identifier(value["system_id"], "system ID")
    policy_hash = _digest(value["policy_hash"], "policy hash")
    dossier_hash = _digest(value["dossier_hash"], "dossier hash")
    access_mode = _plain_text(value["access_mode"], 64, "access mode")
    adapter = _plain_text(value["adapter"], 128, "adapter")
    supported_efforts = _ADAPTER_EFFORTS.get((access_mode, adapter))
    if supported_efforts is None:
        raise ValidationError("access mode and adapter are not an approved pairing")
    effort = _plain_text(value["effort"], 32, "effort")
    if effort not in supported_efforts:
        raise ValidationError("effort is not supported by the adapter")
    role = _plain_text(value["role"], 32, "role")
    if role not in _ROLES:
        raise ValidationError("role is invalid")
    primary_model = _model(value["model"], "model")
    reuse_scope = _plain_text(value["reuse_scope"], 32, "reuse scope")
    if reuse_scope not in _REUSE_SCOPES:
        raise ValidationError("reuse scope is invalid")
    max_calls = _positive_integer(value["max_calls"], "maximum calls")
    if reuse_scope == "single-use" and max_calls != 1:
        raise ValidationError(
            "single-use task selections require maximum calls of exactly one"
        )

    return {
        "task_id": task_id,
        "system_id": system_id,
        "policy_hash": policy_hash,
        "dossier_hash": dossier_hash,
        "access_mode": access_mode,
        "adapter": adapter,
        "account_ref": _account_reference(value["account_ref"]),
        "model": primary_model,
        "effort": effort,
        "role": role,
        "artifact_scope": _artifact_scope(value["artifact_scope"]),
        "fallback": _fallback(value["fallback"], primary_model),
        "max_calls": max_calls,
        "timeout": _positive_integer(value["timeout"], "timeout"),
        "max_output": _positive_integer(value["max_output"], "maximum output"),
        "expires_at": _expiry(value["expires_at"]),
        "reuse_scope": reuse_scope,
    }


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite number")


def _decode_json(value: Any) -> Any:
    if type(value) is not str:
        raise PolicyDenied("task selection metadata is malformed")
    try:
        return json.loads(
            value,
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PolicyDenied("task selection metadata is malformed") from exc


def _result(
    selection: dict[str, Any], uses: int, record_hash: str
) -> dict[str, Any]:
    return {**selection, "uses": uses, "record_hash": record_hash}


class TaskAuthorityStore:
    def __init__(
        self,
        database: Database,
        audit: AuditLog,
        dossier: DossierStore,
    ):
        self.database = database
        self.audit = audit
        self.dossier = dossier

    def _validate_live(self, selection: dict[str, Any], connection: Any) -> None:
        task_rows = connection.execute(
            "SELECT task_id,system_id,policy_hash FROM tasks WHERE task_id=?",
            (selection["task_id"],),
        ).fetchall()
        expected_task = (
            selection["task_id"],
            selection["system_id"],
            selection["policy_hash"],
        )
        if len(task_rows) != 1 or tuple(task_rows[0]) != expected_task:
            raise PolicyDenied("task selection does not match the live task")

        system_rows = connection.execute(
            "SELECT system_id FROM systems WHERE system_id=? AND approved=1",
            (selection["system_id"],),
        ).fetchall()
        if (
            len(system_rows) != 1
            or system_rows[0][0] != selection["system_id"]
        ):
            raise PolicyDenied("task selection system is not approved")

        try:
            current = self.dossier.current(selection["system_id"])
        except (ValidationError, PolicyDenied) as exc:
            raise PolicyDenied("current dossier is unavailable") from exc
        if (
            not isinstance(current, dict)
            or current.get("hash") != selection["dossier_hash"]
        ):
            raise PolicyDenied("task selection does not match the current dossier")

    def _parse(
        self, value: Any, connection: Any
    ) -> tuple[dict[str, Any], int, str]:
        wrapper = _decode_json(value)
        if type(wrapper) is not dict or set(wrapper) != {
            "payload",
            "record_hash",
        }:
            raise PolicyDenied("task selection wrapper shape is invalid")
        payload = wrapper["payload"]
        record_hash = wrapper["record_hash"]
        if (
            type(payload) is not dict
            or set(payload) != {"selection", "uses"}
            or type(record_hash) is not str
            or not _HEX_DIGEST.fullmatch(record_hash)
            or record_hash != sha256_json(payload)
        ):
            raise PolicyDenied("task selection integrity check failed")

        uses = payload["uses"]
        if type(uses) is not int or uses < 0:
            raise PolicyDenied("task selection usage state is invalid")
        try:
            selection = _canonical_selection(payload["selection"])
        except ValidationError as exc:
            raise PolicyDenied("stored task selection is invalid") from exc
        if selection != payload["selection"]:
            raise PolicyDenied("stored task selection is not canonical")
        if uses > selection["max_calls"]:
            raise PolicyDenied("task selection usage state exceeds its limit")
        self._validate_live(selection, connection)
        return selection, uses, record_hash

    @staticmethod
    def _wrapper(
        selection: dict[str, Any], uses: int
    ) -> tuple[dict[str, Any], str]:
        payload = {"selection": selection, "uses": uses}
        record_hash = sha256_json(payload)
        return {"payload": payload, "record_hash": record_hash}, record_hash

    @staticmethod
    def _audit_details(
        selection: dict[str, Any],
        record_hash: str,
        uses: int,
        status: str,
    ) -> dict[str, Any]:
        return {
            "record_hash": record_hash,
            "adapter": selection["adapter"],
            "model_hash": sha256_json(selection["model"]),
            "effort": selection["effort"],
            "role": selection["role"],
            "max_calls": selection["max_calls"],
            "timeout": selection["timeout"],
            "max_output": selection["max_output"],
            "uses": uses,
            "status": status,
        }

    def create(self, selection: dict[str, Any]) -> dict[str, Any]:
        canonical = _canonical_selection(selection)
        key = _selection_key(canonical["task_id"])
        with _translated_storage_conflicts(), self.database.transaction() as connection:
            self._validate_live(canonical, connection)
            rows = connection.execute(
                "SELECT value FROM metadata WHERE key=?", (key,)
            ).fetchall()
            if len(rows) > 1:
                raise PolicyDenied("multiple task selection records found")
            if len(rows) == 1:
                stored, uses, record_hash = self._parse(rows[0][0], connection)
                if stored != canonical:
                    raise ConflictError("task selection is immutable")
                return _result(stored, uses, record_hash)

            wrapper, record_hash = self._wrapper(canonical, 0)
            cursor = connection.execute(
                "INSERT INTO metadata(key,value) VALUES(?,?)",
                (key, self.database.json(wrapper)),
            )
            if cursor.rowcount != 1:
                raise PolicyDenied("task selection could not be recorded")
            self.audit.append(
                "task.selection.created",
                self._audit_details(canonical, record_hash, 0, "created"),
                system_id=canonical["system_id"],
                task_id=canonical["task_id"],
                connection=connection,
            )
        return _result(canonical, 0, record_hash)

    def get(self, task_id: str) -> dict[str, Any]:
        task_id = _identifier(task_id, "task ID")
        key = _selection_key(task_id)
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT value FROM metadata WHERE key=?", (key,)
            ).fetchall()
            if not rows:
                raise AuthorizationRequired("task-selection-required")
            if len(rows) != 1:
                raise PolicyDenied("multiple task selection records found")
            selection, uses, record_hash = self._parse(rows[0][0], connection)
        return _result(selection, uses, record_hash)

    def consume(self, task_id: str, role: Any, artifact: Any) -> dict[str, Any]:
        task_id = _identifier(task_id, "task ID")
        requested_role = _plain_text(role, 32, "role")
        if requested_role not in _ROLES:
            raise ValidationError("role is invalid")
        requested_artifact = _artifact_entry(artifact)
        key = _selection_key(task_id)
        with _translated_storage_conflicts(), self.database.transaction() as connection:
            rows = connection.execute(
                "SELECT value FROM metadata WHERE key=?", (key,)
            ).fetchall()
            if not rows:
                raise AuthorizationRequired("task-selection-required")
            if len(rows) != 1:
                raise PolicyDenied("multiple task selection records found")
            stored_value = rows[0][0]
            selection, uses, _ = self._parse(stored_value, connection)
            if requested_role != selection["role"]:
                raise PolicyDenied(
                    "task selection does not permit the requested role"
                )
            if requested_artifact not in selection["artifact_scope"]:
                raise PolicyDenied(
                    "task selection does not permit the requested artifact"
                )
            if uses >= selection["max_calls"]:
                raise ConflictError("task selection use limit has been reached")

            uses += 1
            wrapper, record_hash = self._wrapper(selection, uses)
            cursor = connection.execute(
                "UPDATE metadata SET value=? WHERE key=? AND value=?",
                (self.database.json(wrapper), key, stored_value),
            )
            if cursor.rowcount != 1:
                raise ConflictError("task selection changed during consumption")
            self.audit.append(
                "task.selection.consumed",
                self._audit_details(selection, record_hash, uses, "consumed"),
                system_id=selection["system_id"],
                task_id=selection["task_id"],
                connection=connection,
            )
        return _result(selection, uses, record_hash)

    def reject_legacy(self, system_id: str) -> None:
        _identifier(system_id, "system ID")
        raise _SelectionMigrationRequired(
            "task-selection-required migration: create an immutable task selection record"
        )

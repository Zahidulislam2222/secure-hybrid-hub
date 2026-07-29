from __future__ import annotations

import hmac
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .audit import AuditLog
from .errors import AuthorizationRequired, ConflictError, PolicyDenied, ValidationError
from .storage import Database
from .util import require_id, sha256_json

_STATUSES = frozenset({"pending", "approved", "consumed"})
_RECORD_FIELDS = frozenset({
    "authority_id",
    "system_id",
    "task_id",
    "action",
    "payload_hash",
    "challenge",
    "expires_at",
    "status",
    "approved_by",
    "approved_at",
    "consumed_at",
})
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MATERIAL_DIRECTORY = "authority"
_MATERIAL_FILE = "phase1-owner-material.bin"
_MATERIAL_BYTES = 32
_MAXIMUM_TTL = timedelta(days=7)
_APPROVER = "owner-detached-proof"


def _authority_key(validated_authority_id: str) -> str:
    return f"action-authority:{validated_authority_id}"


def _new_authority_id() -> str:
    return f"aa-{secrets.token_hex(8)}"


def _new_challenge() -> str:
    return secrets.token_hex(32)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@contextmanager
def _translated_storage_conflicts() -> Iterator[None]:
    try:
        yield
    except sqlite3.IntegrityError as exc:
        raise ConflictError(
            "action authority storage rejected a conflicting write"
        ) from exc
    except sqlite3.OperationalError as exc:
        reason = str(exc).casefold()
        if "locked" in reason or "busy" in reason:
            raise ConflictError("action authority storage is contended") from exc
        raise


def _plain_text(value: Any, limit: int, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValidationError(f"{label} must be a nonempty string")
    if len(value) > limit or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
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
    now = _utc_now()
    if parsed <= now:
        raise ValidationError("action authority expiry is not in the future")
    if parsed > now + _MAXIMUM_TTL:
        raise ValidationError("action authority expiry exceeds the bounded window")
    return parsed.isoformat().replace("+00:00", "Z")


def _stored_timestamp(value: Any, label: str) -> str:
    value = _plain_text(value, 64, label)
    if not value.endswith("Z"):
        raise ValidationError(f"{label} must use an explicit UTC timezone")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValidationError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValidationError(f"{label} must use UTC")
    return value


def _expired(expires_at: str) -> bool:
    parsed = datetime.fromisoformat(expires_at[:-1] + "+00:00")
    return parsed <= _utc_now()


def _proof(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or not _HEX_DIGEST.fullmatch(value)
    ):
        raise ValidationError(
            "proof must be a lowercase hexadecimal HMAC-SHA256 value"
        )
    return value


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
        raise PolicyDenied("action authority metadata is malformed")
    try:
        return json.loads(
            value,
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PolicyDenied("action authority metadata is malformed") from exc


class ApprovalAuthority:
    def __init__(self, database: Database, audit: AuditLog):
        self.database = database
        self.audit = audit

    # -- owner-only synthetic Phase 1 material -----------------------------

    def _material_paths(self) -> tuple[Path, Path]:
        directory = self.database.layout.root / _MATERIAL_DIRECTORY
        return directory, directory / _MATERIAL_FILE

    def _require_private_mode(self, path: Path, expected: int, label: str) -> None:
        info = path.stat()
        observed = stat.S_IMODE(info.st_mode)
        if observed != expected:
            raise PolicyDenied(
                f"{label} cannot enforce required owner-only permissions "
                f"{oct(expected)}; observed {oct(observed)}"
            )
        effective_uid = getattr(os, "geteuid", None)
        if effective_uid is not None and info.st_uid != effective_uid():
            raise PolicyDenied(f"{label} is not owned by the broker user")

    def _material(self) -> bytes:
        directory, path = self._material_paths()
        if not directory.exists():
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
            else:
                os.chmod(directory, 0o700)
        if directory.is_symlink() or not directory.is_dir():
            raise PolicyDenied("authority material directory is invalid")
        self._require_private_mode(directory, 0o700, "authority material directory")
        if not path.exists():
            descriptor, temporary = tempfile.mkstemp(dir=directory)
            try:
                try:
                    os.fchmod(descriptor, 0o600)
                    os.write(descriptor, secrets.token_bytes(_MATERIAL_BYTES))
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    pass
            finally:
                os.unlink(temporary)
        if path.is_symlink():
            raise PolicyDenied("authority material must not be a symlink")
        self._require_private_mode(path, 0o600, "authority material")
        material = path.read_bytes()
        if len(material) != _MATERIAL_BYTES:
            raise PolicyDenied("authority material is invalid")
        return material

    # -- record helpers ----------------------------------------------------

    @staticmethod
    def _wrapper(record: dict[str, Any]) -> tuple[dict[str, Any], str]:
        record_hash = sha256_json(record)
        return {"payload": record, "record_hash": record_hash}, record_hash

    def _parse(self, value: Any) -> tuple[dict[str, Any], str]:
        wrapper = _decode_json(value)
        if type(wrapper) is not dict or set(wrapper) != {"payload", "record_hash"}:
            raise PolicyDenied("action authority wrapper shape is invalid")
        record = wrapper["payload"]
        record_hash = wrapper["record_hash"]
        if (
            type(record) is not dict
            or set(record) != _RECORD_FIELDS
            or type(record_hash) is not str
            or not _HEX_DIGEST.fullmatch(record_hash)
            or record_hash != sha256_json(record)
        ):
            raise PolicyDenied("action authority integrity check failed")
        try:
            _identifier(record["authority_id"], "authority ID")
            _identifier(record["system_id"], "system ID")
            _identifier(record["task_id"], "task ID")
            _identifier(record["action"], "action")
            _digest(record["payload_hash"], "payload hash")
            challenge = record["challenge"]
            if type(challenge) is not str or not _HEX_DIGEST.fullmatch(challenge):
                raise ValidationError("challenge is invalid")
            _stored_timestamp(record["expires_at"], "expiry")
            status = record["status"]
            if status not in _STATUSES:
                raise ValidationError("status is invalid")
            approved_by = record["approved_by"]
            approved_at = record["approved_at"]
            consumed_at = record["consumed_at"]
            if status == "pending":
                if not (approved_by is None and approved_at is None and consumed_at is None):
                    raise ValidationError("pending state is inconsistent")
            else:
                if approved_by != _APPROVER:
                    raise ValidationError("approver is invalid")
                _stored_timestamp(approved_at, "approval time")
                if status == "approved":
                    if consumed_at is not None:
                        raise ValidationError("approved state is inconsistent")
                else:
                    _stored_timestamp(consumed_at, "consumption time")
        except ValidationError as exc:
            raise PolicyDenied("stored action authority is invalid") from exc
        return record, record_hash

    def _fetch(self, connection: Any, validated_authority_id: str) -> tuple[dict[str, Any], str, str]:
        key = _authority_key(validated_authority_id)
        rows = connection.execute(
            "SELECT value FROM metadata WHERE key=?", (key,)
        ).fetchall()
        if not rows:
            raise AuthorizationRequired("action-authority-required")
        if len(rows) != 1:
            raise PolicyDenied("multiple action authority records found")
        record, _ = self._parse(rows[0][0])
        if record["authority_id"] != validated_authority_id:
            raise PolicyDenied("action authority identity mismatch")
        return record, rows[0][0], key

    def _store(
        self,
        connection: Any,
        key: str,
        previous_value: str,
        record: dict[str, Any],
    ) -> str:
        wrapper, record_hash = self._wrapper(record)
        cursor = connection.execute(
            "UPDATE metadata SET value=? WHERE key=? AND value=?",
            (self.database.json(wrapper), key, previous_value),
        )
        if cursor.rowcount != 1:
            raise ConflictError("action authority changed during update")
        return record_hash

    def _audit_details(
        self, record: dict[str, Any], record_hash: str
    ) -> dict[str, Any]:
        return {
            "authority_id": record["authority_id"],
            "action": record["action"],
            "payload_hash": record["payload_hash"],
            "expires_at": record["expires_at"],
            "status": record["status"],
            "record_hash": record_hash,
        }

    # -- public API --------------------------------------------------------

    def issue(
        self,
        system_id: str,
        task_id: str,
        action: str,
        payload_hash: str,
        expires_at: str,
    ) -> dict[str, str]:
        system_id = _identifier(system_id, "system ID")
        task_id = _identifier(task_id, "task ID")
        action = _identifier(action, "action")
        payload_hash = _digest(payload_hash, "payload hash")
        expires_at = _expiry(expires_at)
        self._material()

        authority_id = _new_authority_id()
        challenge = _new_challenge()
        record = {
            "authority_id": authority_id,
            "system_id": system_id,
            "task_id": task_id,
            "action": action,
            "payload_hash": payload_hash,
            "challenge": challenge,
            "expires_at": expires_at,
            "status": "pending",
            "approved_by": None,
            "approved_at": None,
            "consumed_at": None,
        }
        with _translated_storage_conflicts(), self.database.transaction() as connection:
            task_rows = connection.execute(
                "SELECT system_id FROM tasks WHERE task_id=?", (task_id,)
            ).fetchall()
            if len(task_rows) != 1 or task_rows[0][0] != system_id:
                raise PolicyDenied(
                    "action authority does not match a live task binding"
                )
            wrapper, record_hash = self._wrapper(record)
            cursor = connection.execute(
                "INSERT INTO metadata(key,value) VALUES(?,?)",
                (_authority_key(authority_id), self.database.json(wrapper)),
            )
            if cursor.rowcount != 1:
                raise PolicyDenied("action authority could not be recorded")
            self.audit.append(
                "action.authority.issued",
                self._audit_details(record, record_hash),
                system_id=system_id,
                task_id=task_id,
                connection=connection,
            )
        return {
            "authority_id": authority_id,
            "challenge": challenge,
            "expires_at": expires_at,
        }

    def approve(self, authority_id: str, proof: Any) -> dict[str, Any]:
        authority_id = _identifier(authority_id, "authority ID")
        proof = _proof(proof)
        material = self._material()
        with _translated_storage_conflicts(), self.database.transaction() as connection:
            record, previous_value, key = self._fetch(connection, authority_id)
            if record["status"] != "pending":
                raise PolicyDenied("action authority is not pending approval")
            if _expired(record["expires_at"]):
                raise PolicyDenied("action authority has expired")
            expected = hmac.new(
                material,
                record["challenge"].encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, proof):
                raise PolicyDenied("action authority proof is invalid")
            updated = {
                **record,
                "status": "approved",
                "approved_by": _APPROVER,
                "approved_at": _utc_now().isoformat().replace("+00:00", "Z"),
            }
            record_hash = self._store(connection, key, previous_value, updated)
            self.audit.append(
                "action.authority.approved",
                self._audit_details(updated, record_hash),
                system_id=updated["system_id"],
                task_id=updated["task_id"],
                connection=connection,
            )
        return {
            "authority_id": authority_id,
            "status": "approved",
            "approved_by": _APPROVER,
            "record_hash": record_hash,
        }

    def consume(
        self,
        authority_id: str,
        system_id: str,
        task_id: str,
        action: str,
        payload_hash: str,
    ) -> dict[str, Any]:
        authority_id = _identifier(authority_id, "authority ID")
        system_id = _identifier(system_id, "system ID")
        task_id = _identifier(task_id, "task ID")
        action = _identifier(action, "action")
        payload_hash = _digest(payload_hash, "payload hash")
        self._material()
        with _translated_storage_conflicts(), self.database.transaction() as connection:
            record, previous_value, key = self._fetch(connection, authority_id)
            if record["status"] == "consumed" or record["consumed_at"] is not None:
                raise ConflictError("action authority has already been consumed")
            if record["status"] != "approved":
                raise PolicyDenied("action authority is not approved")
            if _expired(record["expires_at"]):
                raise PolicyDenied("action authority has expired")
            bound = (
                record["system_id"],
                record["task_id"],
                record["action"],
                record["payload_hash"],
            )
            requested = (system_id, task_id, action, payload_hash)
            if bound != requested:
                raise PolicyDenied(
                    "action authority does not bind the requested action"
                )
            updated = {
                **record,
                "status": "consumed",
                "consumed_at": _utc_now().isoformat().replace("+00:00", "Z"),
            }
            record_hash = self._store(connection, key, previous_value, updated)
            self.audit.append(
                "action.authority.consumed",
                self._audit_details(updated, record_hash),
                system_id=system_id,
                task_id=task_id,
                connection=connection,
            )
        return {
            "authority_id": authority_id,
            "status": "consumed",
            "record_hash": record_hash,
        }

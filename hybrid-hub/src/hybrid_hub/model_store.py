from __future__ import annotations

import json
from typing import Any

from .audit import AuditLog
from .errors import PolicyDenied, ValidationError
from .storage import Database
from .util import require_id, sha256_json


def require_system(database: Database, system_id: str) -> str:
    require_id(system_id, "system ID")
    with database.connect() as connection:
        row = connection.execute(
            "SELECT 1 FROM systems WHERE system_id=? AND approved=1", (system_id,)
        ).fetchone()
    if not row:
        raise ValidationError("approved system unavailable")
    return system_id


def load_record(database: Database, key: str) -> dict[str, Any] | None:
    with database.connect() as connection:
        row = connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
    if not row:
        return None
    try:
        wrapper = json.loads(row[0])
    except json.JSONDecodeError as exc:
        raise PolicyDenied("model metadata record is malformed") from exc
    if not isinstance(wrapper, dict) or set(wrapper) != {"payload", "record_hash"}:
        raise PolicyDenied("model metadata record shape is invalid")
    payload = wrapper["payload"]
    if not isinstance(payload, dict) or wrapper["record_hash"] != sha256_json(payload):
        raise PolicyDenied("model metadata record integrity check failed")
    return payload


def list_records(database: Database, prefix: str) -> list[dict[str, Any]]:
    with database.connect() as connection:
        keys = [row[0] for row in connection.execute(
            "SELECT key FROM metadata WHERE key LIKE ? ORDER BY key", (prefix + "%",)
        ).fetchall()]
    return [record for key in keys if (record := load_record(database, key)) is not None]


def write_record(
    database: Database,
    audit: AuditLog,
    key: str,
    payload: dict[str, Any],
    event_type: str,
    system_id: str,
    actor: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    require_system(database, system_id)
    require_id(actor, "actor")
    wrapper = {"payload": payload, "record_hash": sha256_json(payload)}
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO metadata(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, database.json(wrapper)),
        )
        audit.append(
            event_type,
            {"actor": actor, "record_hash": wrapper["record_hash"], **summary},
            system_id=system_id,
            connection=connection,
        )
    return {**payload, "record_hash": wrapper["record_hash"]}

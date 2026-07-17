from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")


def approved_fixture_entries(database: Any, dossier: Any, repo_id: str) -> dict[str, str]:
    with database.connect() as connection:
        row = connection.execute(
            "SELECT system_id FROM repositories WHERE repo_id=?", (repo_id,)
        ).fetchone()
    if not row:
        return {}
    security = dossier.current(row[0])["payload"].get("security")
    if not isinstance(security, dict) or security.get("status") != "approved":
        return {}
    if security.get("change_id") != "self-hosting-synthetic-fixture-attestation-v1":
        return {}
    record = security.get("fixture_attestation")
    if not isinstance(record, dict) or record.get("schema_version") != "1.0.0":
        return {}
    if record.get("repository_id") != repo_id:
        return {}
    entries = record.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
        return {}
    approved: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            return {}
        relative, digest = entry["path"], entry["sha256"]
        if not isinstance(relative, str) or not isinstance(digest, str):
            return {}
        normalized = PurePosixPath(relative)
        unsafe = (
            not relative
            or relative == "."
            or normalized.is_absolute()
            or normalized.as_posix() != relative
            or any(part in {"", ".", ".."} for part in normalized.parts)
        )
        if unsafe or relative in approved or DIGEST_PATTERN.fullmatch(digest) is None:
            return {}
        approved[relative] = digest
    return approved

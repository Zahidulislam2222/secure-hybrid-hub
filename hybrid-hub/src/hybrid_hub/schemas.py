from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import ValidationError
from .util import canonical_json


class SchemaRegistry:
    """Small fail-closed validator for the hub's versioned artifact catalog.

    It intentionally supports only the constrained schema features used by the
    broker. Unknown artifact kinds and unexpected top-level fields are rejected.
    """

    ENVELOPE = {
        "schema_version",
        "artifact_type",
        "task_id",
        "system_id",
        "classification",
        "policy_hash",
        "created_at",
        "producer",
        "content_hashes",
        "payload",
    }

    def __init__(self, catalog_path: Path, max_bytes: int = 1_048_576):
        self.catalog_path = catalog_path
        self.max_bytes = max_bytes
        try:
            self.catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(f"schema catalog unavailable: {exc}") from exc
        if self.catalog.get("schema_version") != "1.0.0":
            raise ValidationError("unsupported schema catalog version")

    @property
    def kinds(self) -> set[str]:
        return set(self.catalog.get("artifacts", {}))

    def validate(self, artifact: dict[str, Any]) -> None:
        if not isinstance(artifact, dict):
            raise ValidationError("artifact must be an object")
        encoded = canonical_json(artifact)
        if len(encoded) > self.max_bytes:
            raise ValidationError("artifact exceeds size limit")
        unknown = set(artifact) - self.ENVELOPE
        missing = self.ENVELOPE - set(artifact)
        if unknown:
            raise ValidationError(f"unexpected artifact fields: {sorted(unknown)}")
        if missing:
            raise ValidationError(f"missing artifact fields: {sorted(missing)}")
        kind = artifact["artifact_type"]
        definition = self.catalog.get("artifacts", {}).get(kind)
        if definition is None:
            raise ValidationError(f"unknown artifact type: {kind}")
        if artifact["schema_version"] != definition.get("version"):
            raise ValidationError("artifact schema version mismatch")
        if artifact["classification"] not in {"R0", "R1", "R2", "R3", "R4"}:
            raise ValidationError("invalid classification")
        for field in ("task_id", "system_id", "policy_hash", "created_at", "producer"):
            if not isinstance(artifact[field], str) or not artifact[field]:
                raise ValidationError(f"invalid {field}")
        if not isinstance(artifact["content_hashes"], list):
            raise ValidationError("content_hashes must be an array")
        if not isinstance(artifact["payload"], dict):
            raise ValidationError("payload must be an object")
        required = set(definition.get("required_payload", []))
        missing_payload = required - set(artifact["payload"])
        if missing_payload:
            raise ValidationError(f"missing payload fields: {sorted(missing_payload)}")

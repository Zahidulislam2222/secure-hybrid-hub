from __future__ import annotations

from typing import Any

from .audit import AuditLog
from .errors import ConflictError, ValidationError
from .model_contracts import ModelDefinition
from .model_store import list_records, load_record, require_system, write_record
from .storage import Database
from .util import require_id, utc_now


class ModelRegistryBase:
    def __init__(self, database: Database, audit: AuditLog):
        self.database = database
        self.audit = audit

    @staticmethod
    def _key(system_id: str, model_id: str) -> str:
        return f"model:{system_id}:{model_id}"

    def discover(self, system_id: str, definition: dict[str, Any], actor: str) -> dict[str, Any]:
        require_system(self.database, system_id)
        model = ModelDefinition.from_dict(definition)
        key = self._key(system_id, model.model_id)
        if load_record(self.database, key) is not None:
            raise ConflictError("model definition already discovered")
        payload = {
            "system_id": system_id, "status": "quarantined",
            "definition": model.as_dict(), "evaluation": None,
            "approved_by": None, "disabled_by": None, "updated_at": utc_now(),
        }
        return write_record(self.database, self.audit, key, payload, "model.discovered", system_id, actor, {"model_id": model.model_id, "status": "quarantined"})

    def get(self, system_id: str, model_id: str) -> dict[str, Any]:
        require_system(self.database, system_id)
        require_id(model_id, "model ID")
        record = load_record(self.database, self._key(system_id, model_id))
        if record is None or record.get("system_id") != system_id:
            raise ValidationError("project model unavailable")
        ModelDefinition.from_dict(record.get("definition"))
        return record

    def list(self, system_id: str) -> list[dict[str, Any]]:
        require_system(self.database, system_id)
        records = list_records(self.database, f"model:{system_id}:")
        for record in records:
            if record.get("system_id") != system_id:
                raise ValidationError("project model scope mismatch")
            ModelDefinition.from_dict(record.get("definition"))
        return records

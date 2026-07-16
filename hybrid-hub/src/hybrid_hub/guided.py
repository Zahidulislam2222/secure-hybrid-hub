from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

from .audit import AuditLog, SECRET_PATTERNS
from .dossier import DossierStore
from .errors import ConflictError, PolicyDenied, ValidationError
from .research import ResearchManager
from .storage import Database
from .util import bounded_text, canonical_json, require_id, sha256_bytes, sha256_json, utc_now


SUPERVISOR_SOURCES = {
    "codex-interactive",
    "claude-interactive",
    "codex-cloud",
    "claude-cloud",
    "human-approved",
    "synthetic-acceptance",
}
MAX_PACKETS = 64
MAX_PACKET_PATHS = 128
MAX_RESEARCH_ITEMS = 8
SAFE_RELATIVE = re.compile(r"^[^\x00\r\n]{1,512}$")


class GuidedPlanStore:
    """Broker-owned, immutable high-level plans decomposed into local work packets."""

    def __init__(self, database: Database, audit: AuditLog, dossier: DossierStore):
        self.database = database
        self.audit = audit
        self.dossier = dossier

    def submit(self, task_id: str, template: dict[str, Any], source: str) -> dict[str, Any]:
        if source not in SUPERVISOR_SOURCES:
            raise ValidationError("guided plan supervisor source is invalid")
        with self.database.connect() as connection:
            task = connection.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            repository_rows = connection.execute(
                "SELECT repo_id FROM repositories WHERE system_id=? ORDER BY repo_id",
                (task["system_id"],),
            ).fetchall() if task else []
        if not task:
            raise ValidationError("unknown task")
        if task["state"] != "SCOPED":
            raise PolicyDenied("guided plan submission requires a SCOPED task")
        clean = self._validate(template, task_id, task["system_id"], {row[0] for row in repository_rows})
        plan_id = f"gp-{uuid.uuid4().hex[:16]}"
        plan_hash = sha256_json(clean)
        now = utc_now()
        with self.database.transaction() as connection:
            if connection.execute("SELECT 1 FROM guided_plans WHERE task_id=?", (task_id,)).fetchone():
                raise ConflictError("task already has an immutable guided plan")
            connection.execute(
                "INSERT INTO guided_plans VALUES(?,?,?,?,?,?,?,?)",
                (plan_id, task_id, task["system_id"], source, "approved", self.database.json(clean), plan_hash, now),
            )
            for sequence, packet in enumerate(clean["packets"], 1):
                connection.execute(
                    "INSERT INTO guided_packets VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (task_id, packet["packet_id"], sequence, "pending", self.database.json(packet), sha256_json(packet), 0, None, None, now),
                )
            checkpoint = self.dossier.checkpoint(
                task["system_id"],
                "guided-plan",
                "PLANNED",
                {
                    "actor": source,
                    "policy_hash": task["policy_hash"],
                    "classification": task["classification"],
                    "evidence": [plan_hash],
                    "packet_count": len(clean["packets"]),
                    "unresolved_risks": clean["unresolved_decisions"],
                },
                task_id=task_id,
                connection=connection,
            )
            connection.execute("UPDATE tasks SET state='PLANNED',reason=NULL,updated_at=? WHERE task_id=?", (now, task_id))
            self.audit.append(
                "guided-plan.approved",
                {"plan_id": plan_id, "source": source, "plan_hash": plan_hash, "packet_count": len(clean["packets"]), "checkpoint_hash": checkpoint},
                system_id=task["system_id"],
                task_id=task_id,
                connection=connection,
            )
        return self.get(task_id)

    def get(self, task_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM guided_plans WHERE task_id=?", (task_id,)).fetchone()
            packets = connection.execute("SELECT * FROM guided_packets WHERE task_id=? ORDER BY sequence", (task_id,)).fetchall()
        if not row:
            raise ValidationError("guided plan is unavailable for this task")
        plan = json.loads(row["plan_json"])
        if sha256_json(plan) != row["plan_hash"]:
            raise PolicyDenied("guided plan integrity failed")
        packet_rows = []
        for item in packets:
            packet = json.loads(item["packet_json"])
            if sha256_json(packet) != item["packet_hash"]:
                raise PolicyDenied("guided packet integrity failed")
            packet_rows.append({**dict(item), "packet": packet})
        return {**dict(row), "plan": plan, "packets": packet_rows}

    def update_packet(self, task_id: str, packet_id: str, status: str, *, attempts: int, result_hash: str | None = None, quality_digest: str | None = None) -> dict[str, Any]:
        if status not in {"pending", "research-ready", "implementing", "repairing", "passed", "blocked"}:
            raise ValidationError("guided packet status is invalid")
        with self.database.transaction() as connection:
            row = connection.execute("SELECT packet_hash FROM guided_packets WHERE task_id=? AND packet_id=?", (task_id, packet_id)).fetchone()
            task = connection.execute("SELECT system_id,classification,policy_hash FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row or not task:
                raise ValidationError("unknown guided packet")
            connection.execute(
                "UPDATE guided_packets SET status=?,attempts=?,result_hash=?,quality_digest=?,updated_at=? WHERE task_id=? AND packet_id=?",
                (status, attempts, result_hash, quality_digest, utc_now(), task_id, packet_id),
            )
            evidence = [item for item in (row["packet_hash"], result_hash, quality_digest) if item]
            checkpoint = self.dossier.checkpoint(
                task["system_id"],
                f"packet-{packet_id}-{status}-{attempts}",
                "LOCAL_IMPLEMENTING",
                {"actor": "broker", "policy_hash": task["policy_hash"], "classification": task["classification"], "evidence": evidence, "packet_id": packet_id, "packet_status": status, "unresolved_risks": [] if status == "passed" else [f"packet {packet_id} is {status}"]},
                task_id=task_id,
                connection=connection,
            )
            self.audit.append(
                "guided-packet.updated",
                {"packet_id": packet_id, "status": status, "attempts": attempts, "result_hash": result_hash, "quality_digest": quality_digest, "checkpoint_hash": checkpoint},
                system_id=task["system_id"], task_id=task_id, connection=connection,
            )
        return self.get(task_id)

    @staticmethod
    def _validate(template: Any, task_id: str, system_id: str, repositories: set[str]) -> dict[str, Any]:
        required = {"outcome", "non_goals", "acceptance_criteria", "packets", "final_test_strategy", "unresolved_decisions"}
        if not isinstance(template, dict) or set(template) != required:
            raise ValidationError("guided plan fields are incomplete or unknown")
        bounded_text(template["outcome"], 8192, "guided plan outcome")
        for field, limit in (("non_goals", 32), ("acceptance_criteria", 64), ("final_test_strategy", 64), ("unresolved_decisions", 32)):
            values = template[field]
            if not isinstance(values, list) or len(values) > limit or any(not isinstance(item, str) or not item.strip() or len(item.encode()) > 4096 for item in values):
                raise ValidationError(f"guided plan {field} is invalid")
        packets = template["packets"]
        if not isinstance(packets, list) or not 1 <= len(packets) <= MAX_PACKETS:
            raise ValidationError("guided plan requires 1 to 64 work packets")
        clean_packets = []
        seen: set[str] = set()
        for packet in packets:
            fields = {"packet_id", "title", "objective", "repository_ids", "allowed_paths", "context_paths", "deliverables", "depends_on", "acceptance_criteria", "test_focus", "research", "research_required", "research_guidance"}
            if not isinstance(packet, dict) or set(packet) != fields:
                raise ValidationError("guided packet fields are incomplete or unknown")
            packet_id = packet["packet_id"]
            require_id(packet_id, "packet ID")
            if packet_id in seen:
                raise ValidationError("guided packet IDs must be unique")
            seen.add(packet_id)
            bounded_text(packet["title"], 512, "packet title")
            bounded_text(packet["objective"], 4096, "packet objective")
            repo_ids = packet["repository_ids"]
            if not isinstance(repo_ids, list) or not repo_ids or len(repo_ids) > 8 or set(repo_ids) - repositories:
                raise PolicyDenied("guided packet repository scope is invalid")
            path_fields: dict[str, dict[str, list[str]]] = {}
            for field in ("allowed_paths", "context_paths"):
                mapping = packet[field]
                if not isinstance(mapping, dict) or set(mapping) != set(repo_ids):
                    raise PolicyDenied(f"guided packet {field} must map every and only selected repository")
                normalized_mapping: dict[str, list[str]] = {}
                total_paths = 0
                for repo_id, values in mapping.items():
                    if not isinstance(values, list) or not values:
                        raise ValidationError(f"guided packet {field} is invalid for {repo_id}")
                    total_paths += len(values)
                    normalized = []
                    for value in values:
                        if not isinstance(value, str) or not SAFE_RELATIVE.fullmatch(value):
                            raise ValidationError(f"guided packet {field} contains an invalid path")
                        path = Path(value)
                        if path.is_absolute() or ".." in path.parts or any(part in {".git", ".env", "secrets"} for part in path.parts):
                            raise PolicyDenied(f"guided packet {field} escapes approved source scope")
                        normalized.append(path.as_posix().rstrip("/") or ".")
                    normalized_mapping[repo_id] = sorted(set(normalized))
                if total_paths > MAX_PACKET_PATHS:
                    raise ValidationError(f"guided packet {field} is invalid")
                path_fields[field] = normalized_mapping
            deliverables = packet["deliverables"]
            if not isinstance(deliverables, list) or not 1 <= len(deliverables) <= 32:
                raise ValidationError("guided packet deliverables are invalid")
            clean_deliverables = []
            seen_deliverables: set[tuple[str, str]] = set()
            for deliverable in deliverables:
                if not isinstance(deliverable, dict) or set(deliverable) != {"repo_id", "path", "purpose", "instructions"}:
                    raise ValidationError("guided packet deliverable fields are invalid")
                repo_id, relative = deliverable["repo_id"], deliverable["path"]
                if repo_id not in repo_ids or not isinstance(relative, str) or not SAFE_RELATIVE.fullmatch(relative):
                    raise PolicyDenied("guided packet deliverable is outside repository scope")
                normalized = Path(relative)
                if normalized.is_absolute() or ".." in normalized.parts or any(part in {".git", ".env", "secrets"} for part in normalized.parts):
                    raise PolicyDenied("guided packet deliverable path is forbidden")
                normalized_text = normalized.as_posix()
                if not any(prefix == "." or normalized_text == prefix or normalized_text.startswith(prefix.rstrip("/") + "/") for prefix in path_fields["allowed_paths"][repo_id]):
                    raise PolicyDenied("guided packet deliverable exceeds allowed paths")
                bounded_text(deliverable["purpose"], 1024, "deliverable purpose")
                bounded_text(deliverable["instructions"], 4096, "deliverable instructions")
                key = (repo_id, normalized_text)
                if key in seen_deliverables:
                    raise ValidationError("guided packet deliverables must be unique")
                seen_deliverables.add(key)
                clean_deliverables.append({"repo_id": repo_id, "path": normalized_text, "purpose": deliverable["purpose"], "instructions": deliverable["instructions"]})
            dependencies = packet["depends_on"]
            if not isinstance(dependencies, list) or len(dependencies) > MAX_PACKETS or any(item not in seen for item in dependencies):
                raise ValidationError("guided packet dependencies must reference earlier packets")
            for field in ("acceptance_criteria", "test_focus"):
                values = packet[field]
                if not isinstance(values, list) or not values or len(values) > 32 or any(not isinstance(item, str) or not item.strip() or len(item.encode()) > 2048 for item in values):
                    raise ValidationError(f"guided packet {field} is invalid")
            research = packet["research"]
            if not isinstance(research, list) or len(research) > MAX_RESEARCH_ITEMS:
                raise ValidationError("guided packet research is invalid")
            clean_research = []
            for item in research:
                if not isinstance(item, dict) or set(item) != {"query", "official_urls"}:
                    raise ValidationError("guided research item is invalid")
                ResearchManager._validate_query(item["query"])
                urls = item["official_urls"]
                if not isinstance(urls, list) or len(urls) > 5 or any(not isinstance(url, str) or len(url.encode()) > 4096 for url in urls):
                    raise ValidationError("guided official research URLs are invalid")
                clean_research.append({"query": item["query"], "official_urls": urls})
            if not isinstance(packet["research_required"], bool) or (packet["research_required"] and not clean_research):
                raise ValidationError("guided packet research_required is invalid")
            research_guidance = packet["research_guidance"]
            if not isinstance(research_guidance, list) or len(research_guidance) > 32 or any(not isinstance(item, str) or not item.strip() or len(item.encode()) > 2048 for item in research_guidance):
                raise ValidationError("guided packet research guidance is invalid")
            clean_packets.append({**json.loads(json.dumps(packet)), **path_fields, "repository_ids": sorted(set(repo_ids)), "deliverables": clean_deliverables, "research": clean_research})
        clean = json.loads(json.dumps(template))
        clean.update({"schema_version": "1.0.0", "task_id": task_id, "system_id": system_id, "packets": clean_packets})
        encoded = canonical_json(clean)
        if len(encoded) > 512 * 1024:
            raise ValidationError("guided plan exceeds the broker limit")
        for pattern in SECRET_PATTERNS:
            if pattern.search(encoded.decode("utf-8")):
                raise PolicyDenied("guided plan contains credential-like material")
        return clean


class EvidencePacketBuilder:
    """Transforms isolated research results into bounded, provenance-rich model context."""

    def __init__(self, research: ResearchManager, audit: AuditLog):
        self.research = research
        self.audit = audit

    def build(self, task_id: str, packet: dict[str, Any]) -> dict[str, Any]:
        items = []
        degraded: list[str] = []
        for request in packet["research"]:
            result = self.research.resolve(task_id, request["query"], request["official_urls"])
            degraded.extend(result["degraded_reasons"])
            for summary in result["evidence"]:
                evidence = self.research.get_evidence(task_id, summary["evidence_id"])
                items.append({
                    "evidence_id": evidence["evidence_id"], "source_url": evidence["source_url"],
                    "retrieved_at": evidence["retrieved_at"], "content_hash": evidence["content_hash"],
                    "untrusted_evidence": True, "content_is_instruction": False,
                    "prompt_injection_detected": evidence.get("prompt_injection_detected", False),
                    "raw_content_available_to_local_model": False,
                })
        digest = sha256_json({"packet_id": packet["packet_id"], "items": items, "degraded": degraded})
        self.audit.append("guided-research.packet-built", {"packet_id": packet["packet_id"], "evidence_count": len(items), "evidence_packet_hash": digest, "degraded_count": len(degraded)}, task_id=task_id)
        return {"items": items, "degraded_reasons": sorted(set(degraded)), "evidence_packet_hash": digest}

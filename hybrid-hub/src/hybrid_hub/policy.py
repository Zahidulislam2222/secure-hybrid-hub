from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import PolicyDenied, ValidationError
from .util import sha256_json

RANK = {f"R{i}": i for i in range(5)}

MANAGED_GLOBAL = {"classification": "R0", "cloud_code_egress": False, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 36500, "gates": set()}

PROFILES: dict[str, dict[str, Any]] = {
    "regulated": {"classification": "R1", "cloud_code_egress": True, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 30, "gates": {"parse", "unit", "secret-scan", "test-integrity"}},
    "standard": {"classification": "R1", "cloud_code_egress": True, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 90, "gates": {"parse", "unit", "secret-scan"}},
    "confidential": {"classification": "R1", "cloud_code_egress": False, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 14, "gates": {"selected-source-only", "human-egress-approval"}},
    "healthcare": {"classification": "R2", "cloud_code_egress": False, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 14, "gates": {"phi-scan", "audit-completeness", "privacy-retention"}},
    "legal": {"classification": "R4", "cloud_code_egress": False, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 14, "gates": {"privilege-scan", "citation-verification", "matter-separation"}},
    "gdpr": {"classification": "R2", "cloud_code_egress": False, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 30, "gates": {"pii-scan", "retention", "transfer-record"}},
    "financial": {"classification": "R2", "cloud_code_egress": False, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 30, "gates": {"reconciliation", "segregation-of-duties"}},
    "high-secret": {"classification": "R4", "cloud_code_egress": False, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 7, "gates": {"no-project-egress", "independent-review"}},
    "production-critical": {"classification": "R2", "cloud_code_egress": False, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 30, "gates": {"staging", "canary", "rollback", "human-production-approval"}},
    "public-open-source": {"classification": "R0", "cloud_code_egress": True, "internet_with_repo": False, "model_secret_access": False, "production_model_access": False, "retention_days": 90, "gates": {"secret-scan", "licence"}},
}


@dataclass(frozen=True)
class EffectivePolicy:
    profiles: tuple[str, ...]
    classification: str
    cloud_code_egress: bool
    internet_with_repo: bool
    model_secret_access: bool
    production_model_access: bool
    retention_days: int
    gates: tuple[str, ...]
    policy_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "profiles": list(self.profiles),
            "classification": self.classification,
            "cloud_code_egress": self.cloud_code_egress,
            "internet_with_repo": self.internet_with_repo,
            "model_secret_access": self.model_secret_access,
            "production_model_access": self.production_model_access,
            "retention_days": self.retention_days,
            "gates": list(self.gates),
            "policy_hash": self.policy_hash,
        }


def compose(profiles: list[str], layers: list[dict[str, Any]] | None = None, *, managed: dict[str, Any] | None = None) -> EffectivePolicy:
    ordered = ["regulated", *profiles]
    ordered = list(dict.fromkeys(ordered))
    unknown = [name for name in ordered if name not in PROFILES]
    if unknown:
        raise ValidationError(f"unknown profiles: {unknown}")
    rules = [managed or MANAGED_GLOBAL, *[PROFILES[name] for name in ordered]]
    if layers:
        rules.extend(layers)
    classification = max((rule.get("classification", "R0") for rule in rules), key=RANK.__getitem__)
    booleans = ("cloud_code_egress", "internet_with_repo", "model_secret_access", "production_model_access")
    values = {key: all(bool(rule.get(key, False)) for rule in rules) for key in booleans}
    retention = min(int(rule.get("retention_days", 36500)) for rule in rules)
    gates = sorted({gate for rule in rules for gate in rule.get("gates", set())})
    payload = {"profiles": ordered, "classification": classification, **values, "retention_days": retention, "gates": gates}
    return EffectivePolicy(tuple(ordered), classification, retention_days=retention, gates=tuple(gates), policy_hash=sha256_json(payload), **values)


def require_action(policy: EffectivePolicy, action: str) -> None:
    mapping = {
        "cloud-egress": policy.cloud_code_egress,
        "internet-with-repo": policy.internet_with_repo,
        "model-secret-access": policy.model_secret_access,
        "model-production-access": policy.production_model_access,
    }
    if action not in mapping or not mapping[action]:
        raise PolicyDenied(f"policy denies {action}")

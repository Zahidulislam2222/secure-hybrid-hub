from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .audit import AuditLog
from .errors import AdapterError, AuthorizationRequired, PolicyDenied, ValidationError
from .model_router import ModelRouter

RETRYABLE_CATEGORIES = frozenset({"capacity", "invalid-output", "timeout", "transport"})
STOP_CATEGORIES = frozenset({"account", "authentication", "classification", "egress", "policy", "security"})


class ModelAttemptError(AdapterError):
    def __init__(self, category: str):
        if category not in RETRYABLE_CATEGORIES | STOP_CATEGORIES:
            raise ValidationError("invalid model-attempt failure category")
        self.category = category
        super().__init__(f"model attempt failed: {category}")

    @property
    def retryable(self) -> bool:
        return self.category in RETRYABLE_CATEGORIES


class BoundedModelExecutor:
    def __init__(self, router: ModelRouter, audit: AuditLog):
        self.router = router
        self.audit = audit

    def execute(
        self,
        system_id: str,
        role: str,
        classification: str,
        runner: Callable[[dict[str, Any]], Any],
        *,
        require_structured_output: bool = True,
    ) -> dict[str, Any]:
        if not callable(runner):
            raise ValidationError("model runner must be callable")
        plan = self.router.plan(
            system_id, role, classification,
            require_structured_output=require_structured_output,
        )
        candidates = plan["candidates"][:plan["max_attempts"]]
        last_category: str | None = None
        for attempt, candidate in enumerate(candidates, start=1):
            summary = {
                "model_id": candidate["model_id"],
                "adapter": candidate["adapter"],
                "location": candidate["location"],
                "attempt": attempt,
            }
            self.audit.append("model.route-attempted", summary, system_id=system_id)
            try:
                result = runner(dict(candidate))
            except ModelAttemptError as exc:
                last_category = exc.category
                self.audit.append(
                    "model.route-attempt-failed",
                    {**summary, "category": exc.category, "retryable": exc.retryable},
                    system_id=system_id,
                )
                if not exc.retryable:
                    raise PolicyDenied(f"model fallback stopped on {exc.category} failure") from exc
                continue
            except (PolicyDenied, AuthorizationRequired, ValidationError) as exc:
                self.audit.append(
                    "model.route-stopped",
                    {**summary, "category": type(exc).__name__},
                    system_id=system_id,
                )
                raise
            except Exception as exc:
                self.audit.append(
                    "model.route-stopped",
                    {**summary, "category": "unclassified"},
                    system_id=system_id,
                )
                raise AdapterError("unclassified model failure stopped fallback") from exc
            self.audit.append("model.route-succeeded", summary, system_id=system_id)
            return {"attempt": attempt, "model": candidate, "result": result}
        self.audit.append(
            "model.route-exhausted",
            {"attempts": len(candidates), "last_category": last_category},
            system_id=system_id,
        )
        raise AdapterError("bounded model fallback attempts exhausted")

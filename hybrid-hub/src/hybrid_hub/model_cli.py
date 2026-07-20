from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .errors import HubError, ValidationError
from .hub import Hub
from .model_cli_parser import parser
from .model_runtime import ModelRuntime
from .model_select import interactive_choice, load_catalog, select_model


def read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid {label} file") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be an object")
    return value


def handle(args: Any) -> Any:
    hub = Hub(args.runtime)
    models = ModelRuntime.from_hub(hub)
    action = args.model_action
    if action == "discover":
        return models.registry.discover(args.system_id, read_object(args.definition, "model definition"), args.actor)
    if action == "evaluate":
        return models.registry.record_evaluation(args.system_id, args.model_id, read_object(args.evidence, "model evaluation"), args.actor)
    if action == "approve":
        return models.registry.approve(args.system_id, args.model_id, args.actor)
    if action == "disable":
        return models.registry.disable(args.system_id, args.model_id, args.actor)
    if action == "list":
        return models.registry.list(args.system_id)
    if action == "policy-propose":
        return models.policies.propose(args.system_id, read_object(args.policy, "automation policy"), args.actor)
    if action == "policy-approve":
        return models.policies.approve(args.system_id, args.actor)
    if action == "policy-show":
        return models.policies.active(args.system_id).as_dict()
    if action == "select":
        catalog = load_catalog(args.catalog)
        platform_id, model_id = args.platform, args.model
        if platform_id is None or model_id is None:
            if not sys.stdin.isatty():
                raise ValidationError("provide --platform and --model, or run interactively")
            platform_id, model_id = interactive_choice(catalog, input, lambda line: print(line, file=sys.stderr))
        return select_model(
            models, hub.database, hub.audit, args.system_id, catalog, platform_id, model_id, args.actor,
            endpoint=args.endpoint, http_bridge_executable=args.http_bridge_executable, timeout=args.timeout,
            cli_executable=args.cli_executable, api_base_url=args.api_base_url, api_key_file=args.api_key_file,
            api_version=args.api_version, input_cost_per_mtok=args.input_cost_per_mtok,
            output_cost_per_mtok=args.output_cost_per_mtok, max_task_cost_usd=args.max_task_cost_usd,
            framing_token_overhead=args.framing_token_overhead,
        )
    if action == "route":
        return models.router.plan(args.system_id, args.role, args.classification, require_structured_output=not args.allow_unstructured)
    raise ValidationError("unknown model action")


def main(argv: list[str] | None = None) -> int:
    try:
        result = handle(parser().parse_args(argv))
        payload = {"ok": True, "result": result}
        code = 0
    except HubError as exc:
        payload = {"ok": False, "error": type(exc).__name__, "message": str(exc)}
        code = 2
    print(json.dumps(payload, indent=2, sort_keys=True))
    return code

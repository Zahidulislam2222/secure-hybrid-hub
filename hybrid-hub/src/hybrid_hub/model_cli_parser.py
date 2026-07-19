from __future__ import annotations

import argparse
import os
from pathlib import Path


def default_runtime() -> Path:
    value = os.environ.get("HYBRID_HUB_RUNTIME")
    return Path(value) if value else Path(__file__).resolve().parents[2] / "runtime"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="hub")
    result.add_argument("--runtime", type=Path, default=default_runtime())
    commands = result.add_subparsers(dest="command", required=True)
    model = commands.add_parser("model")
    actions = model.add_subparsers(dest="model_action", required=True)

    discover = actions.add_parser("discover")
    discover.add_argument("system_id")
    discover.add_argument("--definition", type=Path, required=True)
    discover.add_argument("--actor", required=True)

    evaluate = actions.add_parser("evaluate")
    evaluate.add_argument("system_id")
    evaluate.add_argument("model_id")
    evaluate.add_argument("--evidence", type=Path, required=True)
    evaluate.add_argument("--actor", required=True)

    for name in ("approve", "disable"):
        action = actions.add_parser(name)
        action.add_argument("system_id")
        action.add_argument("model_id")
        action.add_argument("--actor", required=True)

    listing = actions.add_parser("list")
    listing.add_argument("system_id")

    propose = actions.add_parser("policy-propose")
    propose.add_argument("system_id")
    propose.add_argument("--policy", type=Path, required=True)
    propose.add_argument("--actor", required=True)

    policy_approve = actions.add_parser("policy-approve")
    policy_approve.add_argument("system_id")
    policy_approve.add_argument("--actor", required=True)

    policy_show = actions.add_parser("policy-show")
    policy_show.add_argument("system_id")

    select = actions.add_parser("select")
    select.add_argument("system_id")
    select.add_argument("--catalog", type=Path, required=True)
    select.add_argument("--platform")
    select.add_argument("--model")
    select.add_argument("--actor", required=True)
    select.add_argument("--endpoint", default="http://127.0.0.1:11434")
    select.add_argument("--http-bridge-executable", help="absolute local curl/curl.exe path for bounded loopback Ollama HTTP")
    select.add_argument("--cli-executable", help="absolute claude/codex executable path for subscription platforms")
    select.add_argument("--api-base-url", help="HTTPS base URL for API platforms")
    select.add_argument("--api-key-file", help="absolute path to a private single-line API key file for API platforms")
    select.add_argument("--api-version", help="anthropic-version header value for the anthropic-api adapter")
    select.add_argument("--input-cost-per-mtok", type=float, help="input token price in USD per million tokens for API platforms")
    select.add_argument("--output-cost-per-mtok", type=float, help="output token price in USD per million tokens for API platforms")
    select.add_argument("--max-task-cost-usd", type=float, help="hard per-task API spend cap in USD for API platforms")
    select.add_argument("--timeout", type=int, default=300)

    route = actions.add_parser("route")
    route.add_argument("system_id")
    route.add_argument("--role", required=True)
    route.add_argument("--classification", choices=["R0", "R1", "R2", "R3", "R4"], required=True)
    route.add_argument("--allow-unstructured", action="store_true")
    return result

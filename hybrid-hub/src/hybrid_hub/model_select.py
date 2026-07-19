from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from .errors import AdapterError, PolicyDenied, ValidationError
from .model_contracts import ModelDefinition
from .model_store import write_record
from .util import bounded_text, require_id, utc_now

# Adapters with a working execution transport in this build. Platforms whose
# adapter is not listed here are shown but refuse selection until their
# adapter phase ships.
IMPLEMENTED_ADAPTERS = frozenset({"codex-local", "claude-local"})
CATALOG_SCHEMA_VERSION = "1.0.0"
PROBE_SYSTEM = "model-probe"
PROBE_REPO = f"{PROBE_SYSTEM}-repo-1"


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValidationError(f"{label} fields are incomplete or unknown")
    return value


def load_catalog(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError("invalid model catalog file") from exc
    catalog = _exact(value, {"schema_version", "notes", "platforms"}, "model catalog")
    if catalog["schema_version"] != CATALOG_SCHEMA_VERSION:
        raise ValidationError("unsupported model catalog schema version")
    notes = catalog["notes"]
    if not isinstance(notes, list) or any(not isinstance(item, str) for item in notes):
        raise ValidationError("model catalog notes are invalid")
    platforms = catalog["platforms"]
    if not isinstance(platforms, list) or not platforms:
        raise ValidationError("model catalog requires at least one platform")
    seen_platforms: set[str] = set()
    seen_models: set[str] = set()
    for platform in platforms:
        entry = _exact(platform, {"platform_id", "label", "adapter", "notes", "models"}, "catalog platform")
        platform_id = require_id(entry["platform_id"], "platform ID")
        if platform_id in seen_platforms:
            raise ValidationError("catalog platform IDs must be unique")
        seen_platforms.add(platform_id)
        bounded_text(entry["label"], 256, "platform label")
        adapter = require_id(entry["adapter"], "platform adapter")
        if not isinstance(entry["notes"], list) or any(not isinstance(item, str) for item in entry["notes"]):
            raise ValidationError("catalog platform notes are invalid")
        models = entry["models"]
        if not isinstance(models, list) or not models:
            raise ValidationError("catalog platform requires at least one model")
        for model in models:
            item = _exact(model, {"model_id", "provider_model", "label", "definition"}, "catalog model")
            model_id = require_id(item["model_id"], "model ID")
            if model_id in seen_models:
                raise ValidationError("catalog model IDs must be unique")
            seen_models.add(model_id)
            bounded_text(item["label"], 256, "model label")
            provider_model = item["provider_model"]
            if not isinstance(provider_model, str) or not provider_model or len(provider_model) > 128 or any(ch.isspace() or ord(ch) < 32 for ch in provider_model):
                raise ValidationError("catalog provider model name is invalid")
            definition = ModelDefinition.from_dict(item["definition"])
            if definition.model_id != model_id:
                raise ValidationError("catalog definition model ID mismatch")
            if definition.adapter != adapter:
                raise ValidationError("catalog definition adapter must match its platform")
    return catalog


def find_choice(catalog: dict[str, Any], platform_id: str, model_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    for platform in catalog["platforms"]:
        if platform["platform_id"] == platform_id:
            for model in platform["models"]:
                if model["model_id"] == model_id:
                    return platform, model
            raise ValidationError(f"model '{model_id}' is not in platform '{platform_id}'")
    raise ValidationError(f"platform '{platform_id}' is not in the catalog")


def interactive_choice(catalog: dict[str, Any], ask: Callable[[str], str], echo: Callable[[str], None]) -> tuple[str, str]:
    """Numbered platform-then-model menu. Unavailable platforms stay visible
    so the developer sees the roadmap, but selecting one fails closed."""
    platforms = catalog["platforms"]
    echo("Choose the coding platform for this project:")
    for index, platform in enumerate(platforms, 1):
        marker = "" if platform["adapter"] in IMPLEMENTED_ADAPTERS else "  [not yet available]"
        echo(f"  {index}. {platform['label']}{marker}")
        for note in platform["notes"]:
            echo(f"       - {note}")
    platform = platforms[_pick(ask, echo, "Platform number: ", len(platforms))]
    models = platform["models"]
    echo(f"Choose the model on {platform['label']}:")
    for index, model in enumerate(models, 1):
        echo(f"  {index}. {model['label']} ({model['provider_model']})")
    model = models[_pick(ask, echo, "Model number: ", len(models))]
    return platform["platform_id"], model["model_id"]


def _pick(ask: Callable[[str], str], echo: Callable[[str], None], prompt: str, count: int) -> int:
    for _ in range(5):
        raw = ask(prompt).strip()
        if raw.isdigit() and 1 <= int(raw) <= count:
            return int(raw) - 1
        echo(f"Enter a number between 1 and {count}.")
    raise ValidationError("no valid selection was made")


def evidence_from_probe_state(state: str) -> dict[str, Any]:
    if state == "VERIFIED":
        return {"synthetic": True, "passed_packets": 1, "total_packets": 1, "security_violations": 0, "invalid_outputs": 0, "accepted_packet_cost_usd": 0.0}
    violations = 1 if state == "BLOCKED_POLICY" else 0
    return {"synthetic": True, "passed_packets": 0, "total_packets": 1, "security_violations": violations, "invalid_outputs": 0 if violations else 1, "accepted_packet_cost_usd": 0.0}


def _probe_plan() -> dict[str, Any]:
    instructions_code = (
        "Write a complete Python module containing exactly one function: "
        "def greet(name: str) -> str. It returns the string 'Hello, ' + name + '!'. "
        "No printing, no input(), no main block, no imports. Output only the raw file content."
    )
    instructions_test = (
        "Write a complete Python unittest module. Import unittest and from greet import greet. "
        "Define class TestGreet(unittest.TestCase) with test_world asserting greet('World') == 'Hello, World!' "
        "and test_empty asserting greet('') == 'Hello, !'. End with: if __name__ == '__main__': unittest.main(). "
        "Output only the raw file content."
    )
    return {
        "outcome": "The probe repository gains greet.py plus a passing unittest in test_greet.py.",
        "non_goals": ["No changes to app.py"],
        "acceptance_criteria": ["greet('World') returns 'Hello, World!'"],
        "packets": [{
            "packet_id": "probe-greet",
            "title": "Synthetic probe packet",
            "objective": "Create a pure greet(name) function and a deterministic unittest proving its behavior.",
            "repository_ids": [PROBE_REPO],
            "allowed_paths": {PROBE_REPO: ["greet.py", "test_greet.py"]},
            "context_paths": {PROBE_REPO: ["app.py"]},
            "deliverables": [
                {"repo_id": PROBE_REPO, "path": "greet.py", "purpose": "The greet function implementation", "instructions": instructions_code},
                {"repo_id": PROBE_REPO, "path": "test_greet.py", "purpose": "Deterministic unittest for greet", "instructions": instructions_test},
            ],
            "depends_on": [],
            "acceptance_criteria": ["Both files exist and the unittest passes"],
            "test_focus": ["greet('World') exact return value"],
            "research": [],
            "research_required": False,
            "research_guidance": [],
        }],
        "final_test_strategy": ["python3 -m unittest discover in the probe repository"],
        "unresolved_decisions": [],
    }


def run_local_probe(provider_model: str, adapter: str, *, endpoint: str, http_bridge_executable: str | None, timeout: int) -> dict[str, Any]:
    """Real one-packet synthetic evaluation in a throwaway runtime. The counts
    recorded as evaluation evidence come from an actual guided run, never from
    catalog claims or model confidence."""
    hub_entry = Path(__file__).resolve().parents[2] / "hub.py"
    with tempfile.TemporaryDirectory(prefix="hub-model-probe-") as tmp_text:
        tmp = Path(tmp_text)
        runtime = tmp / "runtime"
        repo = tmp / "probe-repo"
        repo.mkdir(parents=True)
        (repo / "app.py").write_text('print("probe")\n', encoding="utf-8")
        for argv in (["git", "init", "-q"], ["git", "config", "user.email", "probe@localhost"], ["git", "config", "user.name", "model-probe"], ["git", "add", "-A"], ["git", "commit", "-qm", "probe"]):
            subprocess.run(argv, cwd=repo, check=True, capture_output=True, timeout=30)

        def invoke(*arguments: str, seconds: int = 120) -> dict[str, Any]:
            completed = subprocess.run([sys.executable, str(hub_entry), "--runtime", str(runtime), *arguments], capture_output=True, text=True, timeout=seconds)
            try:
                payload = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise AdapterError(f"model probe produced no result: {completed.stderr.strip()[:200]}") from exc
            if not payload.get("ok"):
                raise AdapterError(f"model probe step failed: {payload.get('message', 'unknown')[:200]}")
            return payload["result"]

        invoke("init-runtime")
        invoke("system", "init", "--id", PROBE_SYSTEM, "--client", "probe", "--name", "Model probe", "--root", str(repo), "--profile", "standard", "--purpose", "Synthetic coding-model evaluation probe")
        invoke("system", "approve", PROBE_SYSTEM, "--approver", "model-probe")
        commands_file = tmp / "quality.json"
        commands_file.write_text(json.dumps([{"command_id": "probe-unit", "gate": "unit", "repository_id": PROBE_REPO, "argv": ["$PYTHON", "-m", "unittest", "discover", "-s", ".", "-p", "test_*.py"]}]), encoding="utf-8")
        command_set = invoke("quality", "propose", PROBE_SYSTEM, "--commands", str(commands_file), "--proposer", "model-probe")
        invoke("quality", "approve", command_set["command_set_id"], "--approver", "model-probe")
        plan_file = tmp / "plan.json"
        plan_file.write_text(json.dumps(_probe_plan()), encoding="utf-8")
        arguments = [
            "run", "Synthetic model evaluation probe", "--system", PROBE_SYSTEM, "--through", "verified",
            "--guided-plan", str(plan_file), "--supervisor-source", "human-approved",
            "--adapter", adapter, "--model", provider_model, "--endpoint", endpoint, "--timeout", str(timeout),
        ]
        if http_bridge_executable:
            arguments += ["--http-bridge-executable", http_bridge_executable]
        result = invoke(*arguments, seconds=timeout * 3 + 120)
        return evidence_from_probe_state(result["task"]["state"])


def select_model(
    models: Any,
    database: Any,
    audit: Any,
    system_id: str,
    catalog: dict[str, Any],
    platform_id: str,
    model_id: str,
    actor: str,
    *,
    endpoint: str,
    http_bridge_executable: str | None,
    timeout: int,
    probe: Callable[..., dict[str, Any]] = run_local_probe,
) -> dict[str, Any]:
    require_id(actor, "actor")
    platform, model = find_choice(catalog, platform_id, model_id)
    adapter = platform["adapter"]
    if adapter not in IMPLEMENTED_ADAPTERS:
        raise PolicyDenied(f"platform '{platform_id}' needs adapter '{adapter}' which is not implemented yet; choose an available platform")
    definition = ModelDefinition.from_dict(model["definition"])
    try:
        existing = models.registry.get(system_id, model_id)
    except ValidationError:
        existing = None
    probed = False
    if existing is None or existing.get("status") != "approved":
        if existing is None:
            models.registry.discover(system_id, model["definition"], actor)
        evidence = probe(model["provider_model"], adapter, endpoint=endpoint, http_bridge_executable=http_bridge_executable, timeout=timeout)
        probed = True
        models.registry.record_evaluation(system_id, model_id, evidence, actor)
        models.registry.approve(system_id, model_id, actor)
    policy = {
        "mode": "pinned",
        "allowed_model_ids": [model_id],
        "preferred_model_ids": [],
        "pinned_model_id": model_id,
        "allowed_cloud_account_profiles": [definition.account_profile] if definition.location == "cloud" else [],
        "allow_cloud": definition.location == "cloud",
        "max_packet_cost_usd": definition.accepted_packet_cost_usd,
        "max_attempts": 1,
        "min_success_rate": 0.0,
    }
    models.policies.propose(system_id, policy, actor)
    models.policies.approve(system_id, actor)
    transport = {
        "system_id": system_id,
        "model_id": model_id,
        "provider_model": model["provider_model"],
        "adapter": adapter,
        "endpoint": endpoint,
        "http_bridge_executable": http_bridge_executable,
        "timeout": timeout,
        "updated_at": utc_now(),
    }
    write_record(database, audit, f"model-transport:{system_id}:{model_id}", transport, "model.transport-recorded", system_id, actor, {"model_id": model_id, "adapter": adapter})
    return {
        "system_id": system_id,
        "platform_id": platform_id,
        "model_id": model_id,
        "provider_model": model["provider_model"],
        "adapter": adapter,
        "probed": probed,
        "model_status": models.registry.get(system_id, model_id)["status"],
        "policy": models.policies.active(system_id).as_dict(),
    }

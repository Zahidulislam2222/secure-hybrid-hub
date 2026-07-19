from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .errors import AuthorizationRequired, HubError, PolicyDenied, ValidationError
from .hub import Hub
from .policy import RANK, compose
from .topology import Topology
from .model_select import selected_transport
from .http_api_worker import DEFAULT_ANTHROPIC_VERSION, HTTP_API_ADAPTERS, HttpApiConfig, HttpApiWorker
from .subscription_worker import SUBSCRIPTION_ADAPTERS, SubscriptionCliConfig, SubscriptionCliWorker
from .workers import LocalAdapterConfig, LocalWorker


def _default_runtime() -> Path:
    return Path(__file__).resolve().parents[2] / "runtime"


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hub", description="Secure local hybrid-AI policy broker")
    parser.add_argument("--runtime", type=Path, default=_default_runtime(), help="broker-owned runtime directory")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-runtime")

    system = sub.add_parser("system")
    system_sub = system.add_subparsers(dest="system_command", required=True)
    init = system_sub.add_parser("init")
    init.add_argument("--id", required=True)
    init.add_argument("--client", required=True)
    init.add_argument("--name", required=True)
    init.add_argument("--root", action="append", required=True)
    init.add_argument("--profile", action="append", default=[])
    init.add_argument("--purpose", required=True)
    discover = system_sub.add_parser("discover")
    discover.add_argument("system_id")
    approve = system_sub.add_parser("approve")
    approve.add_argument("system_id")
    approve.add_argument("--approver", required=True)
    disable = system_sub.add_parser("disable")
    disable.add_argument("system_id")
    disable.add_argument("--actor", required=True)
    show_system = system_sub.add_parser("show")
    show_system.add_argument("system_id")

    dossier = sub.add_parser("dossier")
    dossier_sub = dossier.add_subparsers(dest="dossier_command", required=True)
    show = dossier_sub.add_parser("show")
    show.add_argument("system_id")
    show.add_argument("--include-draft", action="store_true")
    project = dossier_sub.add_parser("export-safe")
    project.add_argument("system_id")
    project.add_argument("--section", action="append", required=True)
    proposals = dossier_sub.add_parser("proposals")
    proposals.add_argument("system_id")
    propose = dossier_sub.add_parser("propose")
    propose.add_argument("system_id")
    propose.add_argument("--changes", type=Path, required=True)
    propose.add_argument("--task")
    decide = dossier_sub.add_parser("decide")
    decide.add_argument("proposal_id")
    decide.add_argument("--approver", required=True)
    decide.add_argument("--reject", action="store_true")

    run = sub.add_parser("run")
    run.add_argument("request")
    run.add_argument("--system", required=True)
    run.add_argument("--classification", default="R1")
    run.add_argument("--task-id")
    run.add_argument("--create-workspaces", action="store_true")
    run.add_argument("--repo", action="append", default=[])
    run.add_argument("--through", choices=["scoped", "local-ready", "verified"], default="local-ready")
    run.add_argument("--adapter", choices=["codex-local", "claude-local", "claude-subscription-cli", "codex-subscription-cli", "anthropic-api", "openai-compatible-api"], default=None)
    run.add_argument("--cli-executable", help="absolute claude/codex executable path for subscription adapters")
    run.add_argument("--endpoint", default="http://127.0.0.1:11434")
    run.add_argument("--api-base-url", help="HTTPS base URL for HTTP API adapters (OpenAI-compatible URLs include the vendor path prefix)")
    run.add_argument("--api-key-file", help="absolute path to a private single-line API key file (never read from environment)")
    run.add_argument("--api-version", default=DEFAULT_ANTHROPIC_VERSION, help="anthropic-version header for the anthropic-api adapter")
    run.add_argument("--input-cost-per-mtok", type=float, help="input token price in USD per million tokens (required for HTTP API adapters)")
    run.add_argument("--output-cost-per-mtok", type=float, help="output token price in USD per million tokens (required for HTTP API adapters)")
    run.add_argument("--max-task-cost-usd", type=float, help="hard per-task API spend cap in USD (required for HTTP API adapters)")
    run.add_argument("--model")
    run.add_argument("--timeout", type=int, default=300)
    run.add_argument("--executable", help="absolute local ollama/ollama.exe path")
    run.add_argument("--http-bridge-executable", help="absolute local curl/curl.exe path for bounded loopback Ollama HTTP")
    run.add_argument("--max-repairs", type=int, default=3)
    run.add_argument("--modifier", help="approved per-project modifier ID")
    run.add_argument("--guided-plan", type=Path, help="broker-validated supervisor plan JSON; enables component-sized guided execution")
    run.add_argument("--supervisor-source", choices=["codex-interactive", "claude-interactive", "human-approved"], help="identity that produced the guided plan")

    plan_command = sub.add_parser("plan")
    plan_sub = plan_command.add_subparsers(dest="plan_command", required=True)
    plan_submit = plan_sub.add_parser("submit")
    plan_submit.add_argument("task_id")
    plan_submit.add_argument("--file", type=Path, required=True)
    plan_submit.add_argument("--source", choices=["codex-interactive", "claude-interactive", "human-approved"], required=True)
    plan_show = plan_sub.add_parser("show")
    plan_show.add_argument("task_id")

    status = sub.add_parser("status")
    status.add_argument("task_id")
    cancel = sub.add_parser("cancel")
    cancel.add_argument("task_id")
    resume = sub.add_parser("resume")
    resume.add_argument("task_id")
    resume.add_argument("--to", required=True)

    local = sub.add_parser("local")
    local_sub = local.add_subparsers(dest="local_command", required=True)
    for action in ("preflight", "run"):
        command = local_sub.add_parser(action)
        command.add_argument("--adapter", choices=["codex-local", "claude-local"], required=True)
        command.add_argument("--endpoint", default="http://127.0.0.1:11434")
        command.add_argument("--model", required=True)
        command.add_argument("--timeout", type=int, default=120)
        command.add_argument("--executable", help="absolute local ollama/ollama.exe path")
        command.add_argument("--http-bridge-executable", help="absolute local curl/curl.exe path for bounded loopback Ollama HTTP")
        if action == "run":
            command.add_argument("task_id")
            command.add_argument("--prompt", required=True)

    workspace = sub.add_parser("workspace")
    workspace_sub = workspace.add_subparsers(dest="workspace_command", required=True)
    create_workspace = workspace_sub.add_parser("create")
    create_workspace.add_argument("task_id")
    create_workspace.add_argument("--repo", action="append", required=True)
    workspace_sub.add_parser("leases")

    release = sub.add_parser("release-manifest")
    release.add_argument("--topology", type=Path, required=True)
    release.add_argument("--revisions", type=Path, required=True)

    stop = sub.add_parser("emergency-stop")
    stop.add_argument("--clear", action="store_true")

    audit = sub.add_parser("audit")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_sub.add_parser("verify")
    audit_sub.add_parser("export")

    research = sub.add_parser("research")
    research_sub = research.add_subparsers(dest="research_command", required=True)
    research_propose = research_sub.add_parser("propose")
    research_propose.add_argument("system_id")
    research_propose.add_argument("--domain", action="append", required=True)
    research_propose.add_argument("--proposer", required=True)
    research_propose.add_argument("--max-bytes", type=int, default=1_048_576)
    research_propose.add_argument("--timeout", type=int, default=20)
    research_propose.add_argument("--minimum-interval", type=int, default=2)
    research_propose.add_argument("--searxng", action="store_true")
    research_approve = research_sub.add_parser("approve")
    research_approve.add_argument("policy_id")
    research_approve.add_argument("--approver", required=True)
    research_approve.add_argument("--enable-live", action="store_true")
    research_show = research_sub.add_parser("show")
    research_show.add_argument("policy_id")
    research_fetch = research_sub.add_parser("fetch")
    research_fetch.add_argument("task_id")
    research_fetch.add_argument("--url", required=True)
    research_discover = research_sub.add_parser("discover")
    research_discover.add_argument("task_id")
    research_discover.add_argument("query")
    research_discover.add_argument("--limit", type=int, default=10)
    research_ingest = research_sub.add_parser("ingest-offline")
    research_ingest.add_argument("task_id")
    research_ingest.add_argument("--url", required=True)
    research_ingest.add_argument("--content", type=Path, required=True)
    research_ingest.add_argument("--media-type", default="text/plain")
    research_search = research_sub.add_parser("search-cache")
    research_search.add_argument("task_id")
    research_search.add_argument("query")
    research_search.add_argument("--limit", type=int, default=5)
    research_get = research_sub.add_parser("get")
    research_get.add_argument("task_id")
    research_get.add_argument("evidence_id")
    research_resolve = research_sub.add_parser("resolve")
    research_resolve.add_argument("task_id")
    research_resolve.add_argument("query")
    research_resolve.add_argument("--official-url", action="append", default=[])

    secret = sub.add_parser("secret")
    secret_sub = secret.add_subparsers(dest="secret_command", required=True)
    secret_propose = secret_sub.add_parser("propose")
    secret_propose.add_argument("system_id")
    secret_propose.add_argument("--capability", type=Path, required=True)
    secret_propose.add_argument("--proposer", required=True)
    secret_approve = secret_sub.add_parser("approve")
    secret_approve.add_argument("capability_id")
    secret_approve.add_argument("--approver", required=True)
    secret_show = secret_sub.add_parser("show")
    secret_show.add_argument("capability_id")
    secret_run = secret_sub.add_parser("run")
    secret_run.add_argument("task_id")
    secret_run.add_argument("capability_id")

    egress = sub.add_parser("egress")
    egress_sub = egress.add_subparsers(dest="egress_command", required=True)
    egress_build = egress_sub.add_parser("build")
    egress_build.add_argument("task_id")
    egress_build.add_argument("--provider", choices=["codex-cloud", "claude-cloud"], required=True)
    egress_build.add_argument("--selections", type=Path, required=True)
    egress_approve = egress_sub.add_parser("approve")
    egress_approve.add_argument("bundle_id")
    egress_approve.add_argument("--approver", required=True)
    egress_show = egress_sub.add_parser("show")
    egress_show.add_argument("bundle_id")

    quality = sub.add_parser("quality")
    quality_sub = quality.add_subparsers(dest="quality_command", required=True)
    quality_propose = quality_sub.add_parser("propose")
    quality_propose.add_argument("system_id")
    quality_propose.add_argument("--commands", type=Path, required=True)
    quality_propose.add_argument("--proposer", required=True)
    quality_approve = quality_sub.add_parser("approve")
    quality_approve.add_argument("command_set_id")
    quality_approve.add_argument("--approver", required=True)
    quality_show = quality_sub.add_parser("show")
    quality_show.add_argument("command_set_id")

    test = sub.add_parser("test")
    test.add_argument("task_id")
    test.add_argument("--scope", choices=["targeted", "full"], default="targeted")

    inspect_egress = sub.add_parser("inspect-egress")
    inspect_egress.add_argument("bundle_id")

    provider = sub.add_parser("provider")
    provider_sub = provider.add_subparsers(dest="provider_command", required=True)
    provider_propose = provider_sub.add_parser("propose")
    provider_propose.add_argument("system_id")
    provider_propose.add_argument("--profile", type=Path, required=True)
    provider_propose.add_argument("--proposer", required=True)
    provider_approve = provider_sub.add_parser("approve")
    provider_approve.add_argument("profile_id")
    provider_approve.add_argument("--approver", required=True)
    provider_approve.add_argument("--enable-live", action="store_true")
    provider_show = provider_sub.add_parser("show")
    provider_show.add_argument("profile_id")

    cloud = sub.add_parser("cloud")
    cloud_sub = cloud.add_subparsers(dest="cloud_command", required=True)
    cloud_preflight = cloud_sub.add_parser("preflight")
    cloud_preflight.add_argument("bundle_id")

    verify = sub.add_parser("verify")
    verify.add_argument("task_id")

    deploy = sub.add_parser("deploy")
    deploy.add_argument("task_id")
    deploy.add_argument("--to", choices=["staging"], required=True)
    deploy.add_argument("--adapter", required=True)

    promote = sub.add_parser("promote")
    promote.add_argument("task_id")
    promote.add_argument("--approval")
    promote.add_argument("--approver")
    promote.add_argument("--adapter")

    operations = sub.add_parser("operations")
    operations_sub = operations.add_subparsers(dest="operations_command", required=True)
    operations_sub.add_parser("access-review")
    operations_sub.add_parser("security-evaluation")
    operations_sub.add_parser("backup")
    verify_backup = operations_sub.add_parser("verify-backup")
    verify_backup.add_argument("backup_id")
    restore_backup = operations_sub.add_parser("restore-backup")
    restore_backup.add_argument("backup_id")
    restore_backup.add_argument("--destination", type=Path, required=True)
    sbom = operations_sub.add_parser("sbom")
    sbom.add_argument("--source", type=Path, required=True)
    retention = operations_sub.add_parser("retention")
    retention.add_argument("--days", type=int, required=True)
    retention.add_argument("--execute", action="store_true")
    operations_sub.add_parser("expire-exceptions")

    integrations = sub.add_parser("integrations")
    integrations_sub = integrations.add_subparsers(dest="integrations_command", required=True)
    integrations_install = integrations_sub.add_parser("install")
    integrations_install.add_argument("--system", required=True)
    integrations_install.add_argument("--project", type=Path, required=True)

    modifier = sub.add_parser("modifier")
    modifier_sub = modifier.add_subparsers(dest="modifier_command", required=True)
    modifier_propose = modifier_sub.add_parser("propose")
    modifier_propose.add_argument("system_id")
    modifier_propose.add_argument("--file", type=Path, required=True)
    modifier_propose.add_argument("--proposer", required=True)
    modifier_approve = modifier_sub.add_parser("approve")
    modifier_approve.add_argument("modifier_id")
    modifier_approve.add_argument("--approver", required=True)
    modifier_show = modifier_sub.add_parser("show")
    modifier_show.add_argument("modifier_id")
    modifier_list = modifier_sub.add_parser("list")
    modifier_list.add_argument("system_id")
    return parser


def _dossier_seed(registration: dict[str, Any], purpose: str, discovery: dict[str, Any]) -> dict[str, Any]:
    components = [component for repository in discovery["repositories"] for component in repository["components"]]
    return {
        "purpose": purpose,
        "scope": {"roots": registration["roots"], "client_id": registration["client_id"]},
        "hierarchy": {"system": registration["system_id"], "repositories": [repository["repo_id"] for repository in discovery["repositories"]], "components": components, "services": [component["id"] for component in components if component.get("type") == "service"], "contracts": [], "environments": ["local-synthetic"]},
        "architecture": {"status": "draft", "dependencies": []},
        "approved_commands": [],
        "data_classification": registration["policy"]["classification"],
        "policy_profiles": registration["policy"]["profiles"],
        "quality_gates": registration["policy"]["gates"],
        "provenance": [{"source": "human-registration", "verified_at": registration.get("created_at", "registration-time"), "confidence": "human-approval-required"}],
        "known_unknowns": ["component topology requires deterministic discovery and approval"],
    }


def _handle(hub: Hub, args: argparse.Namespace) -> Any:
    if args.command == "init-runtime":
        return {"status": "initialized", "runtime": str(hub.database.layout.root), "cloud_enabled": False, "production_enabled": False}
    if args.command == "system":
        if args.system_command == "init":
            registration = hub.registry.register_system(args.id, args.client, args.name, args.root, args.profile)
            discovery = hub.registry.discover(args.id)
            registration["discovery"] = discovery
            registration["dossier_draft_version"] = hub.dossier.create_draft(args.id, _dossier_seed(registration, args.purpose, discovery))
            registration["coding_model"] = f"not chosen yet — run: hub.py model select {args.id} --catalog config/model-catalog.example.json --actor OWNER (interactive when --platform/--model are omitted)"
            return registration
        if args.system_command == "discover":
            return hub.registry.discover(args.system_id)
        if args.system_command == "approve":
            dossier = hub.dossier.current(args.system_id, approved_only=False)
            hub.dossier.approve(args.system_id, dossier["version"], args.approver)
            hub.registry.approve_system(args.system_id, args.approver)
            return {"system_id": args.system_id, "approved": True, "dossier_version": dossier["version"]}
        if args.system_command == "disable":
            hub.registry.disable_system(args.system_id, args.actor)
            return {"system_id": args.system_id, "approved": False, "new_tasks_allowed": False}
        return hub.registry.get_system(args.system_id)
    if args.command == "dossier":
        if args.dossier_command == "show":
            return hub.dossier.current(args.system_id, approved_only=not args.include_draft)
        if args.dossier_command == "export-safe":
            return hub.dossier.safe_projection(args.system_id, args.section)
        if args.dossier_command == "proposals":
            with hub.database.connect() as connection:
                rows = connection.execute("SELECT * FROM dossier_proposals WHERE system_id=? ORDER BY created_at", (args.system_id,)).fetchall()
            return [{**dict(row), "change_json": json.loads(row["change_json"]), "requires_human": bool(row["requires_human"])} for row in rows]
        if args.dossier_command == "propose":
            changes = json.loads(args.changes.read_text(encoding="utf-8"))
            return hub.dossier.propose(args.system_id, changes, task_id=args.task)
        hub.dossier.decide(args.proposal_id, args.approver, not args.reject)
        return {"proposal_id": args.proposal_id, "decision": "rejected" if args.reject else "approved"}
    if args.command == "run":
        if args.guided_plan and args.through != "verified":
            raise ValidationError("guided plan is supported only with --through verified")
        if bool(args.guided_plan) != bool(args.supervisor_source):
            raise ValidationError("guided execution requires both --guided-plan and --supervisor-source")
        if args.guided_plan and args.executable and not args.http_bridge_executable:
            raise AuthorizationRequired("guided file generation cannot use the unbounded Ollama CLI; configure the pinned local curl HTTP bridge")
        system = hub.registry.get_system(args.system)
        policy = compose(system["profiles"])
        classification = max((args.classification, system["classification"]), key=RANK.__getitem__)
        modifier_row = None
        if args.modifier:
            modifier_row = hub.modifiers.get(args.modifier)
            if modifier_row["system_id"] != args.system or modifier_row["status"] != "approved":
                raise PolicyDenied("selected modifier is not approved for this system")
            classification = max((classification, modifier_row["modifier"]["classification_floor"]), key=RANK.__getitem__)
        worker = None
        adapter = args.adapter
        model = args.model
        endpoint, bridge, cli_executable = args.endpoint, args.http_bridge_executable, args.cli_executable
        api_base_url, api_key_file, api_version = args.api_base_url, args.api_key_file, args.api_version
        input_cost, output_cost, max_task_cost = args.input_cost_per_mtok, args.output_cost_per_mtok, args.max_task_cost_usd
        if args.through == "verified":
            if not model:
                selection = selected_transport(hub.database, hub.audit, args.system)
                if selection:
                    adapter = adapter or selection["adapter"]
                    model = selection["provider_model"]
                    endpoint = selection.get("endpoint") or endpoint
                    bridge = bridge or selection.get("http_bridge_executable")
                    cli_executable = cli_executable or selection.get("cli_executable")
                    api_base_url = api_base_url or selection.get("api_base_url")
                    api_key_file = api_key_file or selection.get("api_key_file")
                    api_version = selection.get("api_version") or api_version
                    input_cost = input_cost if input_cost is not None else selection.get("input_cost_per_mtok")
                    output_cost = output_cost if output_cost is not None else selection.get("output_cost_per_mtok")
                    max_task_cost = max_task_cost if max_task_cost is not None else selection.get("max_task_cost_usd")
                    hub.audit.append("model.selection-used", {"model_id": selection["model_id"], "adapter": adapter, "provider_model": model}, system_id=args.system)
            if not model:
                raise AuthorizationRequired("verified orchestration requires an explicitly selected model: pass --model or configure one with `model select`")
            adapter = adapter or "codex-local"
            if modifier_row and model not in modifier_row["modifier"]["allowed_local_models"]:
                raise PolicyDenied("selected local model is not allowed by the project modifier")
            if adapter in SUBSCRIPTION_ADAPTERS:
                if not args.guided_plan:
                    raise PolicyDenied("subscription adapters support guided plans only")
                subscription_config = SubscriptionCliConfig(adapter, cli_executable, model, args.timeout)
                worker = SubscriptionCliWorker(hub.database, hub.audit, hub.leases, subscription_config)
            elif adapter in HTTP_API_ADAPTERS:
                if not args.guided_plan:
                    raise PolicyDenied("HTTP API adapters support guided plans only")
                if not api_base_url or not api_key_file or input_cost is None or output_cost is None or max_task_cost is None:
                    raise AuthorizationRequired("HTTP API adapters require --api-base-url, --api-key-file, --input-cost-per-mtok, --output-cost-per-mtok, and --max-task-cost-usd (or a stored model selection carrying them)")
                api_config = HttpApiConfig(adapter, api_base_url, model, api_key_file, input_cost, output_cost, max_task_cost, api_version=api_version, timeout=args.timeout)
                worker = HttpApiWorker(hub.database, hub.audit, hub.leases, api_config, hub.provider_profiles)
            else:
                config = LocalAdapterConfig(adapter, endpoint, model, args.timeout, executable=args.executable, http_bridge_executable=bridge)
                worker = LocalWorker(hub.database, hub.audit, hub.leases, config)
            worker.preflight()
        task = hub.tasks.create(args.system, args.request, classification, policy.policy_hash, args.task_id)
        if modifier_row:
            hub.modifiers.bind(task["task_id"], args.modifier)
        for target in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            task = hub.tasks.transition(task["task_id"], target)
        if args.through == "scoped":
            return task
        if args.through == "verified" and args.guided_plan:
            template = json.loads(args.guided_plan.read_text(encoding="utf-8"))
            plan = hub.orchestrator.submit_guided_plan(task["task_id"], template, args.supervisor_source)
        else:
            plan = hub.orchestrator.plan(task["task_id"]) if args.through == "verified" else None
        workspace = None
        if args.create_workspaces or args.through == "verified":
            repo_ids = args.repo
            if not repo_ids:
                if args.guided_plan:
                    repo_ids = sorted({repo_id for packet in plan["plan"]["packets"] for repo_id in packet["repository_ids"]})
                else:
                    repo_ids = [item["repo_id"] for item in hub.registry.discover(args.system)["repositories"]]
            workspace = hub.workspaces.create(task["task_id"], repo_ids)
        task = hub.tasks.transition(task["task_id"], "WORKSPACES_READY", evidence=[workspace["manifest_hash"]] if workspace else ["local-only-dry-run"])
        if args.through == "verified":
            def driver(task_id, prompt, attempt, role):
                if role.endswith(":file"):
                    return worker.run_file(task_id, prompt)["result"]
                return worker.run_structured(task_id, prompt)["result"]
            if args.guided_plan:
                return hub.orchestrator.complete_guided(task["task_id"], driver, adapter=adapter, max_repairs=args.max_repairs)
            return hub.orchestrator.complete(task["task_id"], driver, adapter=adapter, max_repairs=args.max_repairs)
        return {"task": task, "workspace": workspace, "authorized_scope": "local-ready", "next": "run --through verified with an explicitly selected installed model, or inspect status"}
    if args.command == "plan":
        if args.plan_command == "submit":
            return hub.orchestrator.submit_guided_plan(args.task_id, json.loads(args.file.read_text(encoding="utf-8")), args.source)
        return hub.guided_plans.get(args.task_id)
    if args.command == "status":
        return hub.status(args.task_id)
    if args.command == "cancel":
        return hub.cancel_task(args.task_id)
    if args.command == "resume":
        return hub.tasks.resume(args.task_id, args.to)
    if args.command == "local":
        config = LocalAdapterConfig(args.adapter, args.endpoint, args.model, args.timeout, executable=args.executable, http_bridge_executable=args.http_bridge_executable)
        worker = LocalWorker(hub.database, hub.audit, hub.leases, config)
        return worker.preflight() if args.local_command == "preflight" else worker.run_structured(args.task_id, args.prompt)
    if args.command == "workspace":
        return hub.workspaces.create(args.task_id, args.repo) if args.workspace_command == "create" else hub.leases.list()
    if args.command == "release-manifest":
        definition = json.loads(args.topology.read_text(encoding="utf-8"))
        revisions = json.loads(args.revisions.read_text(encoding="utf-8"))
        topology = Topology(definition["components"], definition.get("dependencies", []))
        return topology.release_manifest(revisions, definition["deployment_order"])
    if args.command == "emergency-stop":
        hub.database.set_emergency_stop(not args.clear)
        hub.audit.append("emergency-stop.cleared" if args.clear else "emergency-stop.activated", {"active": not args.clear})
        return {"emergency_stop": not args.clear}
    if args.command == "audit":
        return {"valid": hub.audit.verify()} if args.audit_command == "verify" else hub.audit.export()
    if args.command == "research":
        if args.research_command == "propose":
            return hub.research_policies.propose(args.system_id, args.domain, args.proposer, max_bytes=args.max_bytes, timeout=args.timeout, minimum_interval=args.minimum_interval, searxng=args.searxng)
        if args.research_command == "approve":
            return hub.research_policies.approve(args.policy_id, args.approver, enable_live=args.enable_live)
        if args.research_command == "show":
            return hub.research_policies.get(args.policy_id)
        if args.research_command == "fetch":
            return hub.research.fetch(args.task_id, args.url)
        if args.research_command == "discover":
            return hub.research.discover(args.task_id, args.query, args.limit)
        if args.research_command == "ingest-offline":
            inbox = (hub.database.layout.root / "research-inbox").resolve()
            inbox.mkdir(parents=True, exist_ok=True, mode=0o700)
            content_path = args.content.resolve(strict=True)
            if content_path.is_symlink() or not content_path.is_relative_to(inbox) or not content_path.is_file():
                raise ValidationError(f"offline research content must be a regular file under {inbox}")
            content = content_path.read_text(encoding="utf-8")
            return hub.research.ingest_offline(args.task_id, args.url, content, args.media_type)
        if args.research_command == "search-cache":
            return hub.research.search_cache(args.task_id, args.query, args.limit)
        if args.research_command == "resolve":
            return hub.research.resolve(args.task_id, args.query, args.official_url)
        return hub.research.get_evidence(args.task_id, args.evidence_id)
    if args.command == "secret":
        if args.secret_command == "propose":
            capability = json.loads(args.capability.read_text(encoding="utf-8"))
            return hub.capabilities.propose(args.system_id, capability, args.proposer)
        if args.secret_command == "approve":
            return hub.capabilities.approve(args.capability_id, args.approver)
        if args.secret_command == "show":
            return hub.capabilities.get(args.capability_id)
        raise AuthorizationRequired("no real secret backend is configured; synthetic backends are test-only and cannot be supplied through the CLI")
    if args.command == "egress":
        if args.egress_command == "build":
            selections = json.loads(args.selections.read_text(encoding="utf-8"))
            if not isinstance(selections, list):
                raise ValidationError("egress selections file must contain a JSON list")
            return hub.egress.build(args.task_id, args.provider, selections)
        if args.egress_command == "approve":
            return hub.egress.approve(args.bundle_id, args.approver)
        return hub.egress.get(args.bundle_id)
    if args.command == "inspect-egress":
        return hub.egress.get(args.bundle_id)
    if args.command == "provider":
        if args.provider_command == "propose":
            return hub.provider_profiles.propose(args.system_id, json.loads(args.profile.read_text(encoding="utf-8")), args.proposer)
        if args.provider_command == "approve":
            return hub.provider_profiles.approve(args.profile_id, args.approver, enable_live=args.enable_live)
        return hub.provider_profiles.get(args.profile_id)
    if args.command == "cloud":
        return hub.cloud.preflight(args.bundle_id)
    if args.command == "quality":
        if args.quality_command == "propose":
            commands = json.loads(args.commands.read_text(encoding="utf-8"))
            if not isinstance(commands, list):
                raise ValidationError("quality commands file must contain a JSON list")
            return hub.quality_registry.propose(args.system_id, commands, args.proposer)
        if args.quality_command == "approve":
            return hub.quality_registry.approve(args.command_set_id, args.approver)
        return hub.quality_registry.get(args.command_set_id)
    if args.command == "test":
        return hub.run_quality(args.task_id, args.scope)
    if args.command == "verify":
        return hub.orchestrator.final_report(args.task_id)
    if args.command == "deploy":
        raise AuthorizationRequired("deployment interface is active but no approved project-local CI/CD transport is configured")
    if args.command == "promote":
        if args.approver and not args.approval:
            return hub.deployments.approve_production(args.task_id, args.approver)
        raise AuthorizationRequired("production promotion requires a valid single-use approval and an approved project-local CI/CD transport")
    if args.command == "operations":
        if args.operations_command == "access-review":
            return hub.operations.access_review()
        if args.operations_command == "security-evaluation":
            return hub.operations.security_evaluation()
        if args.operations_command == "backup":
            return hub.operations.backup()
        if args.operations_command == "verify-backup":
            return hub.operations.verify_backup(args.backup_id)
        if args.operations_command == "restore-backup":
            return hub.operations.restore_backup(args.backup_id, args.destination)
        if args.operations_command == "sbom":
            return hub.operations.sbom(args.source)
        if args.operations_command == "retention":
            return hub.operations.retention(args.days, execute=args.execute)
        return hub.operations.expire_exceptions()
    if args.command == "integrations":
        return hub.integrations.install(args.system, args.project, Path(__file__).resolve().parents[2] / "hub.py", args.runtime)
    if args.command == "modifier":
        if args.modifier_command == "propose":
            return hub.modifiers.propose(args.system_id, json.loads(args.file.read_text(encoding="utf-8")), args.proposer)
        if args.modifier_command == "approve":
            return hub.modifiers.approve(args.modifier_id, args.approver)
        if args.modifier_command == "list":
            return hub.modifiers.list(args.system_id)
        return hub.modifiers.get(args.modifier_id)
    raise ValidationError("unsupported command")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = _handle(Hub(args.runtime), args)
        _print({"ok": True, "result": result})
        return 0
    except (HubError, OSError, json.JSONDecodeError) as exc:
        _print({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

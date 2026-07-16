from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .errors import AuthorizationRequired, HubError, ValidationError
from .hub import Hub
from .policy import RANK, compose
from .topology import Topology
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
    run.add_argument("--through", choices=["scoped", "local-ready"], default="local-ready")

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

    for name in ("research", "inspect-egress", "test", "verify", "deploy", "promote"):
        blocked = sub.add_parser(name)
        blocked.add_argument("arguments", nargs="*")
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
        system = hub.registry.get_system(args.system)
        policy = compose(system["profiles"])
        classification = max((args.classification, system["classification"]), key=RANK.__getitem__)
        task = hub.tasks.create(args.system, args.request, classification, policy.policy_hash, args.task_id)
        for target in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            task = hub.tasks.transition(task["task_id"], target)
        if args.through == "scoped":
            return task
        workspace = None
        if args.create_workspaces:
            workspace = hub.workspaces.create(task["task_id"], args.repo)
        task = hub.tasks.transition(task["task_id"], "WORKSPACES_READY", evidence=[workspace["manifest_hash"]] if workspace else ["local-only-dry-run"])
        return {"task": task, "workspace": workspace, "authorized_scope": "phases-0-through-3", "next": "local worker preflight or later phase authorization"}
    if args.command == "status":
        return hub.tasks.get(args.task_id)
    if args.command == "cancel":
        return hub.tasks.cancel(args.task_id)
    if args.command == "resume":
        return hub.tasks.resume(args.task_id, args.to)
    if args.command == "local":
        config = LocalAdapterConfig(args.adapter, args.endpoint, args.model, args.timeout, executable=args.executable)
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
    if args.command in {"research", "inspect-egress", "test", "verify", "deploy", "promote"}:
        raise AuthorizationRequired(f"{args.command} belongs to a later build phase and is not activated; safe resume: implement the next authorized phase from docs/FINAL_BUILD_PLAN.md")
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

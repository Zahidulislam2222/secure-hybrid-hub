from __future__ import annotations

from pathlib import Path

from .audit import AuditLog
from .dossier import DossierStore
from .leases import LeaseManager
from .quality import QualityRegistry
from .self_hosting_quality import AttestedQualityRunner
from .research import ResearchManager, ResearchPolicyStore
from .egress import EgressBuilder
from .cloud import CloudAdapter, ProviderProfileStore
from .deploy import DeploymentManager
from .operations import OperationsManager
from .orchestrator import Orchestrator
from .integrations import IntegrationInstaller
from .modifiers import ModifierStore
from .guided import EvidencePacketBuilder, GuidedPlanStore
from .secrets import CapabilityRegistry, SecretRunner
from .registry import Registry
from .state import TaskManager
from .storage import Database, RuntimeLayout
from .workspaces import WorkspaceManager


class Hub:
    def __init__(self, runtime: Path):
        self.database = Database(RuntimeLayout(runtime))
        self.audit = AuditLog(self.database)
        self.dossier = DossierStore(self.database, self.audit)
        self.registry = Registry(self.database, self.audit)
        self.tasks = TaskManager(self.database, self.audit, self.dossier)
        self.leases = LeaseManager(self.database)
        self.workspaces = WorkspaceManager(self.database, self.audit, self.leases)
        self.quality_registry = QualityRegistry(self.database, self.audit, self.dossier)
        self.quality = AttestedQualityRunner(self.database, self.audit, self.dossier, self.quality_registry)
        self.research_policies = ResearchPolicyStore(self.database, self.audit)
        self.research = ResearchManager(self.database, self.audit, self.research_policies)
        self.capabilities = CapabilityRegistry(self.database, self.audit)
        self.secret_runner = SecretRunner(self.database, self.audit, self.capabilities)
        self.egress = EgressBuilder(self.database, self.audit)
        self.provider_profiles = ProviderProfileStore(self.database, self.audit)
        self.cloud = CloudAdapter(self.database, self.audit, self.egress, self.provider_profiles)
        self.orchestrator = Orchestrator(self.database, self.audit, self.dossier, self.tasks, self.quality)
        self.deployments = DeploymentManager(self.database, self.audit, self.tasks)
        self.operations = OperationsManager(self.database, self.audit)
        self.integrations = IntegrationInstaller(self.database, self.audit, Path(__file__).resolve().parents[3])
        self.modifiers = ModifierStore(self.database, self.audit, self.dossier)
        self.guided_plans = GuidedPlanStore(self.database, self.audit, self.dossier)
        self.research_packets = EvidencePacketBuilder(self.research, self.audit)
        self.orchestrator.guided_plans = self.guided_plans
        self.orchestrator.research_packets = self.research_packets
        self.orchestrator.modifiers = self.modifiers
        self.orchestrator.leases = self.leases
        self.quality.modifiers = self.modifiers
        self.cloud.modifiers = self.modifiers
        self.deployments.modifiers = self.modifiers
        self.research.modifiers = self.modifiers
        self.secret_runner.modifiers = self.modifiers

    def run_quality(self, task_id: str, scope: str):
        task = self.tasks.get(task_id)
        if scope == "targeted":
            if task["state"] == "WORKSPACES_READY":
                task = self.tasks.transition(task_id, "LOCAL_IMPLEMENTING", evidence=["broker-observed-workspace"])
            if task["state"] == "LOCAL_IMPLEMENTING":
                self.tasks.transition(task_id, "TARGETED_TESTING")
        elif scope == "full" and task["state"] == "TARGETED_TESTING":
            targeted = self.quality.latest(task_id, "targeted")
            if not targeted["passed"]:
                from .errors import PolicyDenied

                raise PolicyDenied("full quality gates require passing targeted evidence")
            self.tasks.transition(task_id, "FULL_QUALITY_GATES", evidence=[targeted["evidence_digest"]])
        return self.quality.run(task_id, scope)

    def cancel_task(self, task_id: str):
        task = self.tasks.cancel(task_id)
        released = self.leases.release_owner(task_id)
        self.audit.append("task.resources-released", {"released_leases": released, "workspaces_preserved": True}, system_id=task["system_id"], task_id=task_id)
        return {**task, "released_leases": released, "workspaces_preserved": True}

    def status(self, task_id: str):
        task = self.tasks.get(task_id)
        modifier = self.modifiers.for_task(task_id)
        with self.database.connect() as connection:
            checkpoints = [dict(row) for row in connection.execute("SELECT checkpoint_id,phase,state,checkpoint_hash,created_at FROM checkpoints WHERE task_id=? ORDER BY created_at", (task_id,)).fetchall()]
            quality = [dict(row) for row in connection.execute("SELECT run_id,scope,passed,evidence_digest,created_at FROM quality_runs WHERE task_id=? ORDER BY created_at", (task_id,)).fetchall()]
            releases = [dict(row) for row in connection.execute("SELECT release_id,status,manifest_hash,created_at FROM release_records WHERE task_id=? ORDER BY created_at", (task_id,)).fetchall()]
        leases = [item for item in self.leases.list() if item["owner"] == task_id]
        return {**task, "modifier": None if modifier is None else {"modifier_id": modifier["modifier_id"], "name": modifier["name"], "modifier_hash": modifier["modifier_hash"]}, "checkpoints": checkpoints, "quality_runs": quality, "releases": releases, "active_leases": leases, "audit_valid": self.audit.verify()}

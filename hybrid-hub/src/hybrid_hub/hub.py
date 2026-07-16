from __future__ import annotations

from pathlib import Path

from .audit import AuditLog
from .dossier import DossierStore
from .leases import LeaseManager
from .quality import QualityRegistry, QualityRunner
from .research import ResearchManager, ResearchPolicyStore
from .egress import EgressBuilder
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
        self.quality = QualityRunner(self.database, self.audit, self.dossier, self.quality_registry)
        self.research_policies = ResearchPolicyStore(self.database, self.audit)
        self.research = ResearchManager(self.database, self.audit, self.research_policies)
        self.capabilities = CapabilityRegistry(self.database, self.audit)
        self.secret_runner = SecretRunner(self.database, self.audit, self.capabilities)
        self.egress = EgressBuilder(self.database, self.audit)

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

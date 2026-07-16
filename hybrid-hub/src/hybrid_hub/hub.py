from __future__ import annotations

from pathlib import Path

from .audit import AuditLog
from .dossier import DossierStore
from .leases import LeaseManager
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

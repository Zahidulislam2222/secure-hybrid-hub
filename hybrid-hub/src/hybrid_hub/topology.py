from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .errors import ValidationError
from .util import sha256_json


class Topology:
    def __init__(self, components: list[dict[str, Any]], dependencies: list[dict[str, str]]):
        self.components = {component["id"]: component for component in components}
        self.dependencies = dependencies
        for edge in dependencies:
            if edge.get("from") not in self.components or edge.get("to") not in self.components:
                raise ValidationError("dependency references unknown component")

    def affected(self, changed: set[str], *, include_dependents: bool = True) -> list[str]:
        unknown = changed - set(self.components)
        if unknown:
            raise ValidationError(f"unknown changed components: {sorted(unknown)}")
        graph: dict[str, set[str]] = defaultdict(set)
        for edge in self.dependencies:
            graph[edge["from"]].add(edge["to"])
            if include_dependents:
                graph[edge["to"]].add(edge["from"])
        found = set(changed)
        queue = deque(sorted(changed))
        while queue:
            current = queue.popleft()
            for adjacent in sorted(graph[current]):
                if adjacent not in found:
                    found.add(adjacent)
                    queue.append(adjacent)
        return sorted(found)

    def release_manifest(self, revisions: dict[str, str], deployment_order: list[str]) -> dict[str, Any]:
        missing = set(self.components) - set(revisions)
        if missing:
            raise ValidationError(f"missing component revisions: {sorted(missing)}")
        if set(deployment_order) != set(self.components):
            raise ValidationError("deployment order must contain every component exactly once")
        manifest = {
            "schema_version": "1.0.0",
            "components": [{"component_id": component, "revision": revisions[component]} for component in sorted(revisions)],
            "dependencies": sorted(self.dependencies, key=lambda value: (value["from"], value["to"], value.get("kind", ""))),
            "deployment_order": deployment_order,
            "rollback_order": list(reversed(deployment_order)),
        }
        manifest["manifest_hash"] = sha256_json(manifest)
        return manifest

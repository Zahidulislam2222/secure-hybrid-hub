from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from .fixture_attestation import approved_fixture_entries
from .quality import CLASSIFICATION_CONTENT, SENSITIVE_CONTENT, QualityRunner
from .util import sha256_bytes


class AttestedQualityRunner(QualityRunner):
    def _content_scans(
        self, repository: dict[str, Any], policy_gates: tuple[str, ...]
    ) -> list[dict[str, Any]]:
        findings: dict[str, list[str]] = {"secret-scan": []}
        gates = [gate for gate in CLASSIFICATION_CONTENT if gate in policy_gates]
        findings.update({gate: [] for gate in gates})
        changed = self._changed_paths(repository)
        approved = approved_fixture_entries(
            self.database, self.dossier, repository["repo_id"]
        )
        observed: set[str] = set()
        for path, relative, _ in self._files(repository["workspace_path"]):
            attested = False
            if relative in approved:
                observed.add(relative)
                if relative in changed or sha256_bytes(path.read_bytes()) != approved[relative]:
                    findings["secret-scan"].append(
                        f"attested synthetic fixture changed or digest-mismatched: {relative}"
                    )
                else:
                    attested = True
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                if relative in changed:
                    findings["secret-scan"].append(
                        f"changed binary or non-UTF-8 file requires explicit approval: {relative}"
                    )
                continue
            name = PurePosixPath(relative).name
            if not attested and name.startswith(".env") and not name.endswith(
                (".example", ".sample", ".template")
            ):
                findings["secret-scan"].append(
                    f"environment-value file is forbidden in a coding workspace: {relative}"
                )
            if not attested:
                for detector, pattern in SENSITIVE_CONTENT:
                    if pattern.search(text):
                        findings["secret-scan"].append(f"{detector} finding: {relative}")
            for gate in gates:
                if CLASSIFICATION_CONTENT[gate].search(text):
                    findings[gate].append(f"{gate} finding: {relative}")
        for relative in sorted(set(approved) - observed):
            findings["secret-scan"].append(f"attested synthetic fixture missing: {relative}")
        return [
            self._builtin_result(f"builtin-{gate}", gate, repository["repo_id"], values)
            for gate, values in findings.items()
        ]

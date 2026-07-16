from __future__ import annotations

import os
import re
from pathlib import Path

from .errors import PathDenied

WINDOWS_PATH = re.compile(r"^([A-Za-z]):[\\/](.*)$")


def normalize_runtime_path(raw: str | Path) -> Path:
    text = str(raw)
    match = WINDOWS_PATH.match(text)
    if match:
        drive, tail = match.groups()
        text = f"/mnt/{drive.lower()}/{tail.replace(chr(92), '/')}"
    if "\x00" in text:
        raise PathDenied("NUL in path")
    return Path(text).expanduser()


class SafePaths:
    def __init__(self, roots: list[str | Path]):
        if not roots:
            raise PathDenied("at least one explicit root is required")
        self.roots = [normalize_runtime_path(root).resolve(strict=True) for root in roots]
        if len(set(self.roots)) != len(self.roots):
            raise PathDenied("duplicate or ambiguous roots")
        for index, left in enumerate(self.roots):
            for right in self.roots[index + 1 :]:
                if self._inside(left, right) or self._inside(right, left):
                    raise PathDenied("authorized roots may not overlap")

    @staticmethod
    def _inside(root: Path, candidate: Path) -> bool:
        try:
            return os.path.commonpath([root, candidate]) == str(root)
        except ValueError:
            return False

    def authorize(self, candidate: str | Path, *, must_exist: bool = True) -> Path:
        original = normalize_runtime_path(candidate)
        candidates = [original] if original.is_absolute() else [root / original for root in self.roots]
        authorized: list[Path] = []
        for path in candidates:
            try:
                resolved = path.resolve(strict=must_exist)
            except (OSError, RuntimeError):
                continue
            if any(self._inside(root, resolved) for root in self.roots):
                self._reject_symlink_segments(resolved)
                authorized.append(resolved)
        if len(set(authorized)) == 1:
            return authorized[0]
        if len(set(authorized)) > 1:
            raise PathDenied("relative path is ambiguous across authorized roots")
        raise PathDenied("path is outside authorized roots or unavailable")

    def _reject_symlink_segments(self, candidate: Path) -> None:
        for root in self.roots:
            if not self._inside(root, candidate):
                continue
            relative = candidate.relative_to(root)
            current = root
            for part in relative.parts:
                current = current / part
                if current.exists() and current.is_symlink():
                    raise PathDenied("symlink paths are not authorized")
            return

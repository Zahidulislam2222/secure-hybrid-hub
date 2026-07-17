from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from .errors import ValidationError
from .util import require_id

CLASSIFICATIONS = frozenset(f"R{index}" for index in range(5))
LOCATIONS = frozenset({"local", "cloud"})
MODES = frozenset({"auto", "preferred", "pinned"})


def exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValidationError(f"{label} must contain exactly {sorted(fields)}")
    return value


def ids(value: Any, label: str, *, empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValidationError(f"{label} must be a sequence")
    result = tuple(require_id(item, label) for item in value)
    if (not empty and not result) or len(result) != len(set(result)):
        raise ValidationError(f"{label} must be nonempty and unique")
    return tuple(sorted(result))


def number(value: Any, label: str, minimum: float, maximum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"invalid {label}")
    result = float(value)
    if not math.isfinite(result) or result < minimum or (maximum is not None and result > maximum):
        raise ValidationError(f"invalid {label}")
    return result

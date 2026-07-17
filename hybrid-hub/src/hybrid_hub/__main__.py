from __future__ import annotations

import sys


def _model_command(arguments: list[str]) -> bool:
    index = 2 if len(arguments) >= 2 and arguments[0] == "--runtime" else 0
    return index < len(arguments) and arguments[index] == "model"


if _model_command(sys.argv[1:]):
    from .model_cli import main
else:
    from .cli import main

raise SystemExit(main())

#!/usr/bin/env python3

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))


def _model_command(arguments: list[str]) -> bool:
    index = 2 if len(arguments) >= 2 and arguments[0] == "--runtime" else 0
    return index < len(arguments) and arguments[index] == "model"


if _model_command(sys.argv[1:]):
    from hybrid_hub.model_cli import main
else:
    from hybrid_hub.cli import main

raise SystemExit(main())

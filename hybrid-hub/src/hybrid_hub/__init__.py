"""Secure Hybrid AI Development Hub."""

import os as _os

if _os.name != "posix":
    raise ImportError(
        "Secure Hybrid Hub requires a POSIX platform (Linux, WSL2, or macOS); "
        "native Windows is not supported because the sandbox and quality "
        "runners depend on the Unix-only 'resource' and 'fcntl' modules. "
        "On Windows, run the hub inside WSL2."
    )

__version__ = "0.9.0"

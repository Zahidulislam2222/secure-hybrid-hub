from __future__ import annotations

import ctypes
import fcntl
import os
import socket
import struct
import sys


SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1
IFF_RUNNING = 0x40
PR_SET_NO_NEW_PRIVS = 38
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446

ACCESS_EXECUTE = 1 << 0
ACCESS_WRITE_FILE = 1 << 1
ACCESS_READ_FILE = 1 << 2
ACCESS_READ_DIR = 1 << 3
ACCESS_REMOVE_DIR = 1 << 4
ACCESS_REMOVE_FILE = 1 << 5
ACCESS_MAKE_CHAR = 1 << 6
ACCESS_MAKE_DIR = 1 << 7
ACCESS_MAKE_REG = 1 << 8
ACCESS_MAKE_SOCK = 1 << 9
ACCESS_MAKE_FIFO = 1 << 10
ACCESS_MAKE_BLOCK = 1 << 11
ACCESS_MAKE_SYM = 1 << 12
ACCESS_REFER = 1 << 13
ACCESS_TRUNCATE = 1 << 14
ACCESS_IOCTL_DEV = 1 << 15

BASE_RIGHTS = (
    ACCESS_EXECUTE | ACCESS_WRITE_FILE | ACCESS_READ_FILE | ACCESS_READ_DIR |
    ACCESS_REMOVE_DIR | ACCESS_REMOVE_FILE | ACCESS_MAKE_CHAR | ACCESS_MAKE_DIR |
    ACCESS_MAKE_REG | ACCESS_MAKE_SOCK | ACCESS_MAKE_FIFO | ACCESS_MAKE_BLOCK |
    ACCESS_MAKE_SYM
)
READ_EXECUTE = ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR


class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def _enable_loopback() -> None:
    """Enable only loopback inside a newly created network namespace."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as handle:
            request = struct.pack("16sH14s", b"lo", 0, b"")
            response = fcntl.ioctl(handle.fileno(), SIOCGIFFLAGS, request)
            _, flags, _ = struct.unpack("16sH14s", response)
            request = struct.pack("16sH14s", b"lo", flags | IFF_UP | IFF_RUNNING, b"")
            fcntl.ioctl(handle.fileno(), SIOCSIFFLAGS, request)
    except PermissionError:
        # Some managed WSL/seccomp profiles intentionally prohibit every socket
        # in the new namespace. That is stricter than loopback-only and safe.
        return


def _landlock(allow_root: str, research_network: bool = False) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, 0, 0, LANDLOCK_CREATE_RULESET_VERSION)
    if abi < 1:
        raise OSError(ctypes.get_errno(), "Landlock is unavailable")
    rights = BASE_RIGHTS
    if abi >= 2:
        rights |= ACCESS_REFER
    if abi >= 3:
        rights |= ACCESS_TRUNCATE
    if abi >= 5:
        rights |= ACCESS_IOCTL_DEV
    ruleset_attr = RulesetAttr(rights)
    ruleset_fd = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(ruleset_attr), ctypes.sizeof(ruleset_attr), 0)
    if ruleset_fd < 0:
        raise OSError(ctypes.get_errno(), "cannot create Landlock ruleset")
    opened: list[int] = []
    try:
        paths = [(allow_root, rights)]
        system_paths = ["/usr", "/bin", "/lib", "/lib64"]
        interpreter_prefix = os.path.realpath(sys.base_prefix)
        if not any(interpreter_prefix == p or interpreter_prefix.startswith(p + os.sep) for p in system_paths):
            system_paths.append(interpreter_prefix)
        for system_path in system_paths:
            if os.path.exists(system_path):
                paths.append((system_path, READ_EXECUTE))
        for device in ("/dev/null", "/dev/urandom", "/dev/random"):
            if os.path.exists(device):
                paths.append((device, ACCESS_READ_FILE | ACCESS_WRITE_FILE))
        if research_network:
            for network_file in ("/etc/ssl/certs", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/gai.conf"):
                if os.path.exists(network_file):
                    network_rights = ACCESS_READ_FILE | (ACCESS_READ_DIR if os.path.isdir(network_file) else 0)
                    paths.append((network_file, network_rights))
        for path, allowed in paths:
            descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
            opened.append(descriptor)
            rule = PathBeneathAttr(allowed & rights, descriptor)
            if libc.syscall(SYS_LANDLOCK_ADD_RULE, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(rule), 0) != 0:
                raise OSError(ctypes.get_errno(), f"cannot add Landlock rule for {path}")
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot set no_new_privs")
        if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot enforce Landlock ruleset")
    finally:
        for descriptor in opened:
            os.close(descriptor)
        os.close(ruleset_fd)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 4 or arguments[0] != "--allow-root":
        raise SystemExit("sandbox_exec requires --allow-root PATH [--research-network] -- executable [arguments]")
    allow_root = os.path.realpath(arguments[1])
    if not os.path.isabs(allow_root) or not os.path.isdir(allow_root):
        raise SystemExit("sandbox allow root must be an existing absolute directory")
    index = 2
    research_network = index < len(arguments) and arguments[index] == "--research-network"
    if research_network:
        index += 1
    if index >= len(arguments) or arguments[index] != "--" or index + 1 >= len(arguments):
        raise SystemExit("sandbox executable separator is missing")
    if not research_network:
        _enable_loopback()
    _landlock(allow_root, research_network)
    executable = arguments[index + 1]
    os.execve(executable, arguments[index + 1 :], dict(os.environ))
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

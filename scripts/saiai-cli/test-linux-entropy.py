#!/usr/bin/env python3
"""Run local proxy/TLS lifecycle checks with getrandom returning ENOSYS.

The filter is inherited by every child, including the detached proxy and doctor.
No host policy is changed. All configuration, CA material and traffic belong to
the existing isolated service fixture; no provider/model requests are sent.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import platform
import resource
import subprocess
import sys
from pathlib import Path


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def deny_getrandom() -> None:
    # Native syscall numbers and AUDIT_ARCH constants for our Linux assets.
    architectures = {
        "x86_64": (318, 0xC000003E),
        "aarch64": (278, 0xC00000B7),
    }
    if platform.system() != "Linux" or platform.machine() not in architectures:
        raise RuntimeError("entropy regression requires native Linux x86_64/aarch64")
    syscall_number, audit_arch = architectures[platform.machine()]
    libc = ctypes.CDLL(None, use_errno=True)
    # BPF: verify architecture; load nr; deny getrandom with ENOSYS; allow rest.
    instructions = (SockFilter * 7)(
        SockFilter(0x20, 0, 0, 4),
        SockFilter(0x15, 1, 0, audit_arch),
        SockFilter(0x06, 0, 0, 0x80000000),
        SockFilter(0x20, 0, 0, 0),
        SockFilter(0x15, 0, 1, syscall_number),
        SockFilter(0x06, 0, 0, 0x00050000 | errno.ENOSYS),
        SockFilter(0x06, 0, 0, 0x7FFF0000),
    )
    program = SockFprog(len(instructions), instructions)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:  # SECCOMP_MODE_FILTER
        raise OSError(ctypes.get_errno(), "seccomp filter installation failed")
    sample = ctypes.create_string_buffer(1)
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = libc.syscall(syscall_number, sample, 1, 0)
    if result != -1 or ctypes.get_errno() != errno.ENOSYS:
        raise AssertionError("getrandom ENOSYS injection did not take effect")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    deny_getrandom()
    subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("test-linux-service.py")),
            "--binary",
            str(binary),
        ],
        check=True,
        timeout=180,
    )
    print("SAIAI getrandom ENOSYS regression passed (proxy + doctor TLS)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

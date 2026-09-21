#!/usr/bin/env python3
"""Require the MSVC reproducible-build marker in Windows release binaries.

This catches accidental omission of /Brepro. Exact preview/Release manifest
equality remains the end-to-end reproducibility check before activation.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path


def verify(path: Path) -> None:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("missing DOS header")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE header")
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x20B or optional_size < 168:
        raise ValueError("expected a PE32+ optional header with a debug directory")
    debug_rva, debug_size = struct.unpack_from("<II", data, optional + 160)
    if not debug_rva or not debug_size or debug_size % 28:
        raise ValueError("missing or invalid PE debug directory")
    for index in range(sections):
        section = optional + optional_size + index * 40
        virtual_address, raw_size, raw_offset = struct.unpack_from("<III", data, section + 12)
        offset = debug_rva - virtual_address
        if offset < 0 or offset + debug_size > raw_size:
            continue
        start = raw_offset + offset
        if start + debug_size > len(data):
            raise ValueError("PE debug directory extends past end of file")
        for entry in range(start, start + debug_size, 28):
            if struct.unpack_from("<I", data, entry + 12)[0] == 16:  # IMAGE_DEBUG_TYPE_REPRO
                return
        raise ValueError("missing reproducible-build marker; link Windows assets with /Brepro")
    raise ValueError("PE debug directory is not backed by a section")


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("usage: verify-windows-reproducibility.py <exe> [<exe> ...]")
    for argument in sys.argv[1:]:
        path = Path(argument)
        try:
            verify(path)
        except (OSError, ValueError, struct.error) as error:
            print(f"FAIL: {path.name}: {error}", file=sys.stderr)
            return 1
        print(f"PASS: {path.name} has the reproducible PE build marker")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

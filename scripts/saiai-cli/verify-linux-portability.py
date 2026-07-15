#!/usr/bin/env python3
"""Reject Linux release assets that depend on a host dynamic C runtime."""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
DYNAMIC_ENTRY = struct.Struct("<qQ")

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PF_X = 1
DT_NULL = 0
DT_NEEDED = 1

ASSET_MACHINES = {
    "saiai-linux-x86_64": (62, "x86_64"),
    "saiai-linux-aarch64": (183, "aarch64"),
}
FORBIDDEN_ABI = re.compile(rb"(?:GLIBC|GLIBCXX|CXXABI)_[A-Za-z0-9_.-]+")


class PortabilityError(ValueError):
    """The candidate is not a self-contained Linux release asset."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise PortabilityError(message)


def checked_range(data: bytes, offset: int, size: int, description: str) -> bytes:
    require(offset >= 0 and size >= 0, f"{description} has a negative range")
    end = offset + size
    require(end >= offset and end <= len(data), f"{description} extends past end of file")
    return data[offset:end]


def verify_binary(path: Path) -> str:
    expected = ASSET_MACHINES.get(path.name)
    require(expected is not None, f"unsupported Linux asset name: {path.name}")
    expected_machine, architecture = expected

    data = path.read_bytes()
    require(len(data) >= ELF_HEADER.size, "file is too small for an ELF64 header")
    (
        ident,
        elf_type,
        machine,
        version,
        _entry,
        program_offset,
        _section_offset,
        _flags,
        header_size,
        program_entry_size,
        program_count,
        _section_entry_size,
        _section_count,
        _section_names,
    ) = ELF_HEADER.unpack_from(data)

    require(ident[:4] == ELF_MAGIC, "file is not ELF")
    require(ident[4] == ELFCLASS64, "Linux release asset is not ELF64")
    require(ident[5] == ELFDATA2LSB, "Linux release asset is not little-endian")
    require(ident[6] == EV_CURRENT and version == EV_CURRENT, "ELF version is unsupported")
    require(header_size == ELF_HEADER.size, "ELF header size is unexpected")
    require(elf_type in (ET_EXEC, ET_DYN), "ELF is neither executable nor static PIE")
    require(machine == expected_machine, f"{path.name} is not an {architecture} ELF")
    require(program_count > 0, "ELF has no program headers")
    require(
        program_entry_size >= PROGRAM_HEADER.size,
        "ELF program header entry is too small",
    )
    checked_range(
        data,
        program_offset,
        program_entry_size * program_count,
        "ELF program header table",
    )

    program_headers: list[tuple[int, int, int, int, int, int]] = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        (
            segment_type,
            segment_flags,
            file_offset,
            virtual_address,
            _physical_address,
            file_size,
            memory_size,
            _alignment,
        ) = PROGRAM_HEADER.unpack_from(data, offset)
        require(segment_type != PT_INTERP, "ELF requests a dynamic program interpreter")
        if segment_type in (PT_LOAD, PT_DYNAMIC):
            require(file_size <= memory_size, "ELF segment file size exceeds its memory size")
            checked_range(data, file_offset, file_size, "ELF loadable segment")
        program_headers.append(
            (
                segment_type,
                segment_flags,
                file_offset,
                virtual_address,
                file_size,
                memory_size,
            )
        )

    load_segments = [header for header in program_headers if header[0] == PT_LOAD]
    require(load_segments, "ELF has no loadable segment")
    executable_loads = [
        header for header in load_segments if header[1] & PF_X and header[4] > 0
    ]
    require(executable_loads, "ELF has no file-backed executable load segment")
    require(_entry != 0, "ELF entry point is zero")
    require(
        any(
            virtual_address <= _entry < virtual_address + file_size
            for _, _, _, virtual_address, file_size, _ in executable_loads
        ),
        "ELF entry point is outside its executable load segments",
    )

    for (
        segment_type,
        _segment_flags,
        file_offset,
        virtual_address,
        file_size,
        _memory_size,
    ) in program_headers:
        if segment_type != PT_DYNAMIC:
            continue

        require(file_size > 0, "ELF dynamic segment is empty")
        dynamic_end = file_offset + file_size
        virtual_end = virtual_address + file_size
        require(
            any(
                load_file_offset <= file_offset
                and dynamic_end <= load_file_offset + load_file_size
                and load_virtual_address <= virtual_address
                and virtual_end <= load_virtual_address + load_file_size
                and virtual_address - load_virtual_address == file_offset - load_file_offset
                for (
                    _,
                    _,
                    load_file_offset,
                    load_virtual_address,
                    load_file_size,
                    _,
                ) in load_segments
            ),
            "ELF dynamic segment is not mapped by a loadable segment",
        )

        dynamic = checked_range(data, file_offset, file_size, "ELF dynamic segment")
        require(
            len(dynamic) % DYNAMIC_ENTRY.size == 0,
            "ELF dynamic segment has a partial entry",
        )
        terminated = False
        for dynamic_offset in range(0, len(dynamic), DYNAMIC_ENTRY.size):
            tag, _value = DYNAMIC_ENTRY.unpack_from(dynamic, dynamic_offset)
            require(tag != DT_NEEDED, "ELF declares a DT_NEEDED shared-library dependency")
            if tag == DT_NULL:
                terminated = True
                break
        require(terminated, "ELF dynamic segment is not terminated by DT_NULL")

    forbidden = sorted({match.decode("ascii") for match in FORBIDDEN_ABI.findall(data)})
    require(not forbidden, f"ELF contains forbidden dynamic ABI versions: {', '.join(forbidden)}")
    return architecture


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assets", nargs="+", type=Path)
    return parser.parse_args()


def main() -> int:
    args = arguments()
    for path in args.assets:
        architecture = verify_binary(path)
        print(f"PASS: {path} is a self-contained static Linux {architecture} asset")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PortabilityError) as error:
        print(f"Linux portability verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error

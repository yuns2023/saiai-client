#!/usr/bin/env python3
"""Unit and negative tests for the Linux release portability verifier."""

from __future__ import annotations

import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
VERIFIER_PATH = SCRIPT_DIR / "verify-linux-portability.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("saiai_linux_portability", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Linux portability verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load_verifier()


def elf_fixture(
    machine: int,
    *,
    program_types: tuple[int, ...] = (verifier.PT_LOAD,),
    dynamic_tags: tuple[int, ...] = (),
    terminate_dynamic: bool = True,
    entry: int | None = None,
    load_flags: int = 5,
    load_file_size: int | None = None,
    load_memory_size: int | None = None,
    dynamic_virtual_offset: int = 0,
    suffix: bytes = b"",
) -> bytes:
    base_address = 0x400000
    program_offset = verifier.ELF_HEADER.size
    program_size = verifier.PROGRAM_HEADER.size * len(program_types)
    dynamic = b"".join(verifier.DYNAMIC_ENTRY.pack(tag, 1) for tag in dynamic_tags)
    if verifier.PT_DYNAMIC in program_types and terminate_dynamic:
        dynamic += verifier.DYNAMIC_ENTRY.pack(verifier.DT_NULL, 0)
    dynamic_offset = program_offset + program_size
    code = b"\xc3"
    code_offset = dynamic_offset + len(dynamic)
    total_size = code_offset + len(code) + len(suffix)
    effective_entry = base_address + code_offset if entry is None else entry
    effective_load_file_size = total_size if load_file_size is None else load_file_size
    effective_load_memory_size = (
        effective_load_file_size if load_memory_size is None else load_memory_size
    )

    ident = bytearray(16)
    ident[:4] = verifier.ELF_MAGIC
    ident[4] = verifier.ELFCLASS64
    ident[5] = verifier.ELFDATA2LSB
    ident[6] = verifier.EV_CURRENT
    header = verifier.ELF_HEADER.pack(
        bytes(ident),
        verifier.ET_DYN,
        machine,
        verifier.EV_CURRENT,
        effective_entry,
        program_offset,
        0,
        0,
        verifier.ELF_HEADER.size,
        verifier.PROGRAM_HEADER.size,
        len(program_types),
        0,
        0,
        0,
    )
    programs = []
    for program_type in program_types:
        if program_type == verifier.PT_LOAD:
            flags = load_flags
            payload_offset = 0
            virtual_address = base_address
            payload_size = effective_load_file_size
            memory_size = effective_load_memory_size
            alignment = 0x1000
        elif program_type == verifier.PT_DYNAMIC:
            flags = 4
            payload_offset = dynamic_offset
            virtual_address = base_address + dynamic_offset + dynamic_virtual_offset
            payload_size = len(dynamic)
            memory_size = len(dynamic)
            alignment = 8
        else:
            flags = 4
            payload_offset = code_offset
            virtual_address = base_address + code_offset
            payload_size = len(code)
            memory_size = len(code)
            alignment = 1
        programs.append(
            verifier.PROGRAM_HEADER.pack(
                program_type,
                flags,
                payload_offset,
                virtual_address,
                0,
                payload_size,
                memory_size,
                alignment,
            )
        )
    return header + b"".join(programs) + dynamic + code + suffix


class LinuxPortabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="saiai-linux-portability-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, content: bytes) -> Path:
        path = self.root / name
        path.write_bytes(content)
        return path

    def assert_rejected(self, path: Path, text: str) -> None:
        with self.assertRaisesRegex(verifier.PortabilityError, text):
            verifier.verify_binary(path)

    def test_accepts_static_x86_64_and_aarch64_assets(self) -> None:
        x86 = self.write("saiai-linux-x86_64", elf_fixture(62))
        arm = self.write("saiai-linux-aarch64", elf_fixture(183))
        self.assertEqual(verifier.verify_binary(x86), "x86_64")
        self.assertEqual(verifier.verify_binary(arm), "aarch64")

    def test_rejects_wrong_architecture(self) -> None:
        path = self.write("saiai-linux-aarch64", elf_fixture(62))
        self.assert_rejected(path, "not an aarch64 ELF")

    def test_rejects_program_interpreter(self) -> None:
        path = self.write(
            "saiai-linux-x86_64",
            elf_fixture(
                62,
                program_types=(verifier.PT_LOAD, verifier.PT_INTERP),
            ),
        )
        self.assert_rejected(path, "dynamic program interpreter")

    def test_rejects_needed_shared_library(self) -> None:
        path = self.write(
            "saiai-linux-x86_64",
            elf_fixture(
                62,
                program_types=(verifier.PT_LOAD, verifier.PT_DYNAMIC),
                dynamic_tags=(verifier.DT_NEEDED,),
            ),
        )
        self.assert_rejected(path, "DT_NEEDED")

    def test_rejects_zero_or_unmapped_entry_point(self) -> None:
        for entry in (0, 0x900000):
            with self.subTest(entry=entry):
                path = self.write("saiai-linux-x86_64", elf_fixture(62, entry=entry))
                self.assert_rejected(path, "entry point")

    def test_rejects_missing_executable_load_segment(self) -> None:
        path = self.write("saiai-linux-x86_64", elf_fixture(62, load_flags=4))
        self.assert_rejected(path, "executable load segment")

    def test_rejects_segment_larger_on_disk_than_in_memory(self) -> None:
        path = self.write(
            "saiai-linux-x86_64",
            elf_fixture(62, load_file_size=128, load_memory_size=64),
        )
        self.assert_rejected(path, "file size exceeds")

    def test_rejects_unterminated_or_unmapped_dynamic_segment(self) -> None:
        unterminated = self.write(
            "saiai-linux-x86_64",
            elf_fixture(
                62,
                program_types=(verifier.PT_LOAD, verifier.PT_DYNAMIC),
                dynamic_tags=(2,),
                terminate_dynamic=False,
            ),
        )
        self.assert_rejected(unterminated, "not terminated")

        unmapped = self.write(
            "saiai-linux-x86_64",
            elf_fixture(
                62,
                program_types=(verifier.PT_LOAD, verifier.PT_DYNAMIC),
                dynamic_virtual_offset=1,
            ),
        )
        self.assert_rejected(unmapped, "not mapped")

    def test_rejects_glibc_and_cxx_abi_versions(self) -> None:
        for marker in (b"GLIBC_2.34", b"GLIBCXX_3.4.30", b"CXXABI_1.3", b"GLIBC_PRIVATE"):
            with self.subTest(marker=marker):
                path = self.write("saiai-linux-x86_64", elf_fixture(62, suffix=marker))
                self.assert_rejected(path, "forbidden dynamic ABI versions")

    def test_rejects_truncated_program_table(self) -> None:
        complete = elf_fixture(62)
        truncated_size = verifier.ELF_HEADER.size + verifier.PROGRAM_HEADER.size - 1
        path = self.write("saiai-linux-x86_64", complete[:truncated_size])
        self.assert_rejected(path, "program header table")


if __name__ == "__main__":
    unittest.main()

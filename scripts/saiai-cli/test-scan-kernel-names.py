#!/usr/bin/env python3
"""Self-test for scan-kernel-names.py: every rule fires on a planted
spelling, and ordinary kernel text (the neutral test brand, the private
range, unrelated Base64) stays clean."""

from __future__ import annotations

import base64
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/saiai-cli/scan-kernel-names.py"

spec = importlib.util.spec_from_file_location("scan_kernel_names", SCRIPT)
assert spec and spec.loader
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

NAME = "saiai"

# (file content, rule that must report it)
PLANTED: list[tuple[bytes, str]] = [
    (f"// built for {NAME}\n".encode(), "name"),
    (b'["s", "a", "i", "a", "i"].concat()', "name"),
    (b'[\n    "S",\n    "A",\n    "I",\n    "A",\n    "I",\n]', "name"),
    (b'for v in ["Sai-ai", "x"] {}', "name"),
    (b'"Sai.ai"', "name"),
    (b'"Sai\'ai"', "name"),
    (b'"SAI_AI_HOME"', "name"),
    (b'format!("s{}", "aiai")', "name"),
    (b'env_prefix: "SA$AI_"', "name-masked"),
    (b'"SA\'AI"', "name-masked"),
    (b'"sa.ai"', "name-masked"),
    (b'"Saia_"', "name-masked"),
    (b'"IAIAS"', "name-reversed"),
    (b"fnvnv", "name-rot13"),
    (b"0x73, 0x61, 0x69, 0x61, 0x69", "name-hex"),
    (b"\\x53\\x41\\x49\\x41\\x49", "name-hex"),
    (b"7361696169", "name-hex"),
    (b"%73%61%69%61%69", "name-hex"),
    (b"[115, 97, 105, 97, 105]", "name-decimal"),
    (b"83,65,73,65,73", "name-decimal"),
    (b"api.abapi.example", "internal-name"),
    (b"sub2api", "internal-name"),
    (b"github.com/yuns2023/x", "internal-name"),
    (b"AOGCode", "internal-name"),
    (b"reclaude", "internal-name"),
    (b"http://192.168.1.8:1234", "internal-address"),
    (b"192.168.0.0/24", "internal-address"),
    (b"192.168.0.0/160", "internal-address"),
    (b"ssh stoa@host", "test-machine-user"),
    (b"C:\\Users\\ASUS", "test-machine-user"),
    # Encoded text and binary fixtures.
    (f"x{NAME}y".encode("utf-16-le"), "name"),
    (f"x{NAME.upper()}y".encode("utf-16-be"), "name"),
    (b"\x00\x01\xff\xfe" + NAME.encode() + b"\x00\x02\x80", "name"),
    ("ＳＡＩＡＩ".encode(), "name"),
    # The fragments the publication plan lists, alone.
    *[(fragment.encode(), "name-base64") for fragment in (
        "NhaWFp", "c2FpYWk", "U0FJQUk", "U2FpYWk", "zYWlhaS", "TQUlBS",
    )],
]

for word in (NAME, NAME.upper(), "Saiai", "sAiAi"):
    for prefix in (b"", b"x", b"xy", b"xyz"):
        encoded = base64.b64encode(prefix + word.encode() + b"tail")
        PLANTED.append((encoded, "name-base64"))
        PLANTED.append((base64.urlsafe_b64encode(prefix + word.encode() + b"?>"), "name-base64"))

CLEAN = [
    b'"KTEST_", "Ktest", "Kt-est", "KT$ST_", "KT\'ST"',
    b"localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fe80::/10",
    b"0 : 192.168.0.0/16\n",
    base64.b64encode(bytes(range(256)) * 4),
    b"assistant said: aitp is a local proxy; data mai said",
    b"0x73, 0x61, 0x69, 0x62",
    "ordinary UTF-8 text: café".encode(),
]


def rules_in(content: bytes, name: str = "file.txt") -> set[str]:
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, name).write_bytes(content)
        return {finding.split(": ", 2)[1] for finding in scanner.scan(Path(directory))}


def main() -> int:
    failures = []
    for content, rule in PLANTED:
        found = rules_in(content)
        if rule not in found:
            failures.append(f"missed {rule}: {content!r} (found {sorted(found)})")
    for content in CLEAN:
        found = rules_in(content)
        if found:
            failures.append(f"false positive {sorted(found)}: {content[:80]!r}")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "src").mkdir()
        (root / "src" / f"{NAME}_brand.rs").write_text("fn x() {}\n")
        (root / "fixture.bin").write_text(
            "version https://git-lfs.github.com/spec/v1\noid sha256:00\nsize 1\n"
        )
        (root / ".gitattributes").write_text("*.bin filter=lfs diff=lfs merge=lfs -text\n")
        (root / ".gitmodules").write_text('[submodule "x"]\n\tpath = x\n')
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text("url = https://github.com/yuns2023/x\n")
        try:
            os.symlink("src", root / "link")
        except OSError:
            pass
        findings = "\n".join(scanner.scan(root))
        expected = [
            f"src/{NAME}_brand.rs (path):1: name",
            "fixture.bin: git-lfs pointer",
            ".gitattributes: git-lfs filter",
            ".gitmodules: submodule list",
        ]
        if (root / "link").is_symlink():
            expected.append("link: symbolic link")
        for line in expected:
            if line not in findings:
                failures.append(f"missed {line!r} in:\n{findings}")
        if ".git/config" in findings:
            failures.append(f".git was scanned:\n{findings}")

        # The command line: findings and status 1; a clean tree prints
        # nothing and exits 0.
        dirty = subprocess.run(
            [sys.executable, str(SCRIPT), str(root)], capture_output=True, text=True
        )
        if dirty.returncode != 1 or not dirty.stdout:
            failures.append(f"dirty tree: status {dirty.returncode}, output {dirty.stdout!r}")
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, "clean.rs").write_bytes(CLEAN[0])
        clean = subprocess.run(
            [sys.executable, str(SCRIPT), directory], capture_output=True, text=True
        )
        if clean.returncode != 0 or clean.stdout or clean.stderr:
            failures.append(f"clean tree: status {clean.returncode}, {clean.stdout!r} {clean.stderr!r}")
    missing = subprocess.run(
        [sys.executable, str(SCRIPT), str(ROOT / "no-such-directory")],
        capture_output=True,
        text=True,
    )
    if missing.returncode != 1:
        failures.append(f"a missing directory passed: {missing.stdout!r}")

    for failure in failures:
        print(failure)
    if failures:
        return 1
    print(f"scan-kernel-names: {len(PLANTED)} planted spellings found, {len(CLEAN)} clean texts pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())

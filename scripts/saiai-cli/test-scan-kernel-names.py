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
    # Ordinary code formatting and literal forms.
    (b'[\n        "S",\n        "A",\n        "I",\n        "A",\n        "I",\n]', "name"),
    (b"['S' as u8, 'A' as u8, 'I' as u8, 'A' as u8, 'I' as u8]", "name-literals"),
    (b"[b'S', b'A', b'I', b'A', b'I']", "name-literals"),
    (b"[83u8, 65, 73, 65, 73]", "name-decimal"),
    (b"[\n    0x73,\n        0x61,\n        0x69,\n        0x61,\n        0x69]", "name-hex"),
    (b"['\\x73', '\\u{61}', 'i', 'a', 'i']", "name-literals"),
    (b'concat!("sa",\n            "iai")', "name"),
    (b'concat!("sub", "2api")', "name-literals"),
    # Parts listed side by side count as spelling the name, on purpose.
    (b'assert_eq!("sub", "2api");', "name-literals"),
    (b"['\\u{455}', '\\u{430}', '\\u{456}', '\\u{430}', '\\u{456}']", "name-literals"),
    (b"['\\u{110000}', 's', 'a', 'i', 'a', 'i']", "name-literals"),
    ("S\u0410\u0406\u0410\u0406".encode(), "name"),
    ("s\u00e0\u00ef\u00e1\u00ed".encode(), "name"),
    (b"73006100690061006900", "name-hex"),
    (b"cwBhAGkAYQBpAA==", "name-base64"),
    (b"c2Fp\nYWk=", "name-base64"),
    ("\uff33\uff21\uff29\uff21\uff29".encode("utf-16-le"), "name"),
    (b"\xff\xfe" + "x\u0455aiai".encode("utf-16-le"), "name"),
    (b"/home/stoa/x", "test-machine-user"),
    (b"stoa@host", "test-machine-user"),
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
    b'const PEGASUS: &str = "Pegasus"; // Stoat, asusual',
    b"let ports = [80, 443, 8080]; let bytes = [0x00, 0xff, 0x7f, 0x10];",
    b"let letters = ['a', 'b', 'c']; let x = 115 + 97;",
    b'assert_eq!(render("x"), "KTEST_X"); let v = ["", "a", "ab"];',
    # Invalid escapes (parser negatives, comments) neither crash the scan
    # nor join the literals around them.
    b"// invalid: '\\u{110000}' '\\u{ffffff}' '\\u{d800}' 0x110000",
    b"['s', 'a', '\\u{110000}', 'i', 'a', 'i']",
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
    with tempfile.TemporaryDirectory() as directory:
        # A submodule that is not checked out: only its git metadata, or
        # nothing at all, must not pass as a clean kernel.
        for metadata in (False, True):
            if metadata:
                Path(directory, ".git").write_text("gitdir: ../x\n")
            empty = subprocess.run(
                [sys.executable, str(SCRIPT), directory], capture_output=True, text=True
            )
            if empty.returncode != 1 or "no files to scan" not in empty.stdout:
                failures.append(f"an empty directory passed: {empty.returncode} {empty.stdout!r}")
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

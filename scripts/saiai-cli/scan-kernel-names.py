#!/usr/bin/env python3
"""Fail if a directory meant for the public kernel repository names SAIAI.

Usage: scan-kernel-names.py [DIRECTORY ...]   (default: tools/saiai-cli/kernel)

Every file (and every path) below each directory is read as bytes and
checked in several views: as Latin-1 text (binary files keep their
printable strings), with NUL bytes removed (UTF-16 in either byte order) and,
when it is UTF-8, NFKC-normalized (full-width and other compatibility
spellings). In each view the scan looks for

* the name in any case, spelled out with separators between the letters
  ("s", "a", ... / Sai-ai / s{}aiai), with one letter replaced by a
  symbol (SA$AI), reversed, or ROT13;
* the name's bytes as Base64 / Base64url fragments (every case variant,
  every alignment), as hexadecimal (0x73 / \\x73 / %73 / 7361...), or as
  decimal byte lists;
* internal names and domains, internal addresses (192.168.x.y other than
  the whole private range 192.168.0.0/16) and test machine user names;
* symbolic links, Git LFS pointers and filters, and submodules, which a
  plain file scan would not see through.

Directories named .git are skipped. Findings go to standard output, one per
line, and the exit status is 1; a clean scan prints nothing and exits 0.
This script lives in the SAIAI repository on purpose: the kernel must not
carry the list of names it is checked against.
"""

from __future__ import annotations

import base64
import itertools
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIRECTORY = ROOT / "tools/saiai-cli/kernel"

WORD = "saiai"
# At most this many separator characters between two letters of the name.
GAP = r"[^a-z0-9]{0,8}"


def spelled(word: str) -> re.Pattern[str]:
    return re.compile(GAP.join(re.escape(ch) for ch in word), re.IGNORECASE)


def masked(word: str) -> re.Pattern[str]:
    """The name with one letter replaced by a symbol (SA$AI, Sa'ai, SAIA_)."""
    return re.compile(
        "|".join(
            re.escape(word[:at]) + r"[^a-z0-9\s]" + re.escape(word[at + 1 :])
            for at in range(len(word))
        ),
        re.IGNORECASE,
    )


def rot13(word: str) -> str:
    return word.translate(
        str.maketrans(
            "abcdefghijklmnopqrstuvwxyz", "nopqrstuvwxyzabcdefghijklm"
        )
    )


def case_variants(word: str) -> list[bytes]:
    pairs = [(ch.lower(), ch.upper()) for ch in word]
    return ["".join(choice).encode() for choice in itertools.product(*pairs)]


def base64_fragments(data: bytes) -> set[str]:
    """The Base64 characters that `data` alone determines, at each of the
    three alignments it can take in a longer encoded stream."""
    fragments = set()
    for offset in range(3):
        encoded = base64.b64encode(b"\0" * offset + data + b"\0\0").decode()
        start_bit, end_bit = 8 * offset, 8 * (offset + len(data))
        # Character k covers bits [6k, 6k + 6).
        first = -(-start_bit // 6)
        last = end_bit // 6  # exclusive
        fragments.add(encoded[first:last])
    return {fragment for fragment in fragments if len(fragment) >= 5}


def base64_needles() -> list[str]:
    needles = set()
    for variant in case_variants(WORD):
        for fragment in base64_fragments(variant):
            needles.add(fragment)
            needles.add(fragment.replace("+", "-").replace("/", "_"))
    return sorted(needles)


def hexadecimal_pattern() -> re.Pattern[str]:
    digits = {"s": "[57]3", "a": "[46]1", "i": "[46]9"}
    prefix = r"(?:0x|\\x|\\u\{?0{0,4}|%|&#x)?"
    separator = r"[\s,;:_\-}]{0,3}"
    return re.compile(
        separator.join(prefix + digits[ch] for ch in WORD), re.IGNORECASE
    )


def decimal_pattern() -> re.Pattern[str]:
    codes = {"s": "(?:115|83)", "a": "(?:97|65)", "i": "(?:105|73)"}
    return re.compile(
        r"(?<!\d)" + r"\s*[,;]\s*".join(codes[ch] for ch in WORD) + r"(?!\d)"
    )


RULES: list[tuple[str, re.Pattern[str]]] = [
    ("name", spelled(WORD)),
    ("name-masked", masked(WORD)),
    ("name-reversed", spelled(WORD[::-1])),
    ("name-rot13", spelled(rot13(WORD))),
    ("name-base64", re.compile("|".join(re.escape(n) for n in base64_needles()))),
    ("name-hex", hexadecimal_pattern()),
    ("name-decimal", decimal_pattern()),
    (
        "internal-name",
        re.compile(
            r"abapi|sub2api|yuns2023|saiai\.top|aogcode|reclaude|codex@saiai",
            re.IGNORECASE,
        ),
    ),
    ("internal-address", re.compile(r"192\.168\.(?!0\.0/16(?![\d.]))")),
    ("test-machine-user", re.compile(r"stoa|asus", re.IGNORECASE)),
]

LFS_POINTER = re.compile(r"^version https://git-lfs\.github\.com/spec/", re.MULTILINE)
LFS_FILTER = re.compile(r"filter\s*=\s*lfs", re.IGNORECASE)


def views(data: bytes) -> list[tuple[str, str]]:
    result = [("", data.decode("latin-1"))]
    if b"\0" in data:
        result.append((" (NUL bytes removed)", data.replace(b"\0", b"").decode("latin-1")))
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    else:
        normalized = unicodedata.normalize("NFKC", text)
        if normalized != text:
            result.append((" (NFKC)", normalized))
    return result


def excerpt(text: str, start: int, end: int) -> str:
    around = text[max(0, start - 30) : end + 30]
    return around.encode("unicode_escape").decode("ascii")


def scan_text(label: str, text: str) -> list[str]:
    findings = []
    for rule, pattern in RULES:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                f"{label}:{line}: {rule}: {excerpt(text, match.start(), match.end())}"
            )
    return findings


def scan_file(path: Path, relative: str) -> list[str]:
    findings = []
    data = path.read_bytes()
    seen = set()
    for suffix, text in views(data):
        for finding in scan_text(relative + suffix, text):
            # The same match in several views is reported once.
            key = finding.split(":", 2)[2]
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    text = data.decode("latin-1")
    if LFS_POINTER.search(text):
        findings.append(f"{relative}: git-lfs pointer")
    if path.name == ".gitattributes" and LFS_FILTER.search(text):
        findings.append(f"{relative}: git-lfs filter")
    if path.name == ".gitmodules":
        findings.append(f"{relative}: submodule list")
    return findings


def scan(directory: Path) -> list[str]:
    findings = []
    if not directory.is_dir():
        return [f"{directory}: not a directory"]
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if ".git" in path.relative_to(directory).parts:
            continue
        findings.extend(scan_text(f"{relative} (path)", relative))
        if path.is_symlink():
            findings.append(f"{relative}: symbolic link")
        elif path.is_file():
            findings.extend(scan_file(path, relative))
    return findings


def main(arguments: list[str]) -> int:
    directories = [Path(argument) for argument in arguments] or [DEFAULT_DIRECTORY]
    findings = [
        f"{directory}/{finding}" for directory in directories for finding in scan(directory)
    ]
    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

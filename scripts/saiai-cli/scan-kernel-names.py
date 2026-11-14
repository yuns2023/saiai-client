#!/usr/bin/env python3
"""Fail if a directory meant for the public kernel repository names SAIAI.

Usage: scan-kernel-names.py [DIRECTORY ...]   (default: tools/saiai-cli/kernel)

Every file (and every path) below each directory is read as bytes and
checked in several views: as Latin-1 text (binary files keep their
printable strings), with NUL bytes removed, decoded as UTF-16 in either
byte order, and (UTF-8 / UTF-16) with compatibility forms, accents and
common Cyrillic/Greek look-alike letters folded to ASCII. In each view the scan looks for

* the name in any case, spelled out with separators between the letters
  or as a run of character / byte literals ('S' as u8, b'S', 0x53, 83u8)
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
# Between two letters of the name: any white space (indentation of a
# multi-line array) and at most eight other separator characters.
GAP = r"\s*(?:[^a-z0-9\s]\s*){0,8}"


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
        encodings = [variant] + [
            variant.decode().encode(codec) for codec in ("utf-16-le", "utf-16-be")
        ]
        for fragment in {f for encoded in encodings for f in base64_fragments(encoded)}:
            needles.add(fragment)
            needles.add(fragment.replace("+", "-").replace("/", "_"))
    return sorted(needles)


def hexadecimal_pattern() -> re.Pattern[str]:
    # Also as UTF-16 (a 00 byte before or after each letter).
    digits = {"s": "[57]3", "a": "[46]1", "i": "[46]9"}
    prefix = r"(?:0x|\\x|\\u\{?0{0,4}|%|&#x)?(?:00)?"
    separator = r"(?:00)?(?:u8)?\s*[,;:_\-}]{0,3}\s*"
    return re.compile(
        separator.join(prefix + digits[ch] for ch in WORD), re.IGNORECASE
    )


def decimal_pattern() -> re.Pattern[str]:
    codes = {"s": "(?:115|83)", "a": "(?:97|65)", "i": "(?:105|73)"}
    return re.compile(
        r"(?<!\d)" + r"(?:_?u8)?\s*[,;]\s*".join(codes[ch] for ch in WORD) + r"(?!\d)"
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
    ("test-machine-user", re.compile(r"(?<![a-z])(?:stoa|asus)(?![a-z])", re.IGNORECASE)),
]
BASE64_RULE = next(pattern for rule, pattern in RULES if rule == "name-base64")
INTERNAL_NAMES = next(pattern for rule, pattern in RULES if rule == "internal-name")

# One character as a literal: 'S', b'S', "S", '\x53', '\u{53}', 0x53, 83u8,
# optionally cast ('S' as u8, 83 as char).
LITERAL = re.compile(
    r"""(?:b?'(?P<char>\\x[0-9a-f]{2}|\\u\{[0-9a-f]{1,6}\}|[^'\\\n])'"""
    r'|b?"(?P<string>[^"\\\n]{1,4})"'
    r"|(?<![0-9a-z_])0x(?P<hex>[0-9a-f]{1,2})(?:_?u8)?(?![0-9a-z])"
    r"|(?<![0-9a-z_.])(?P<decimal>[0-9]{2,3})(?:_?u8)?(?![0-9a-z.]))"
    r"(?:\s+as\s+(?:u8|char|u16|u32))?",
    re.IGNORECASE,
)
# What may stand between two literals of one spelled-out value.
LITERAL_GAP = re.compile(r"[\s,;+&|()\[\]{}]*")

CONFUSABLE = str.maketrans(
    {
        "\u0430": "a", "\u0410": "A", "\u03b1": "a", "\u0391": "A",
        "\u0456": "i", "\u0406": "I", "\u03b9": "i", "\u0399": "I",
        "\u0131": "i", "\u04cf": "i", "\u04c0": "I", "\u0455": "s", "\u0405": "S",
        "\ua4e2": "S", "\ua4ee": "A", "\u01c0": "I",
    }
)


def character(number: int) -> str | None:
    """The character with this code, if it is a Unicode scalar value."""
    if 0 <= number < 0x110000 and not 0xD800 <= number <= 0xDFFF:
        return chr(number)
    return None


def literal_value(match: re.Match[str]) -> str | None:
    """The literal's text, or None when it is no valid character."""
    if match["char"] is not None:
        value = match["char"]
        if value.startswith("\\x"):
            return character(int(value[2:], 16))
        if value.startswith("\\u"):
            return character(int(value[3:-1], 16))
        return value
    if match["string"] is not None:
        return match["string"]
    number = int(match["hex"], 16) if match["hex"] is not None else int(match["decimal"])
    return character(number)


def literal_runs(text: str) -> list[tuple[int, str]]:
    """Adjacent character literals joined: (offset, value) per run. On
    purpose this joins across arguments, tuples and arrays alike (the scan
    cannot tell a constructed name from a list of its parts); an invalid
    literal ends a run."""
    runs: list[tuple[int, str]] = []
    start, value, end = 0, "", -1
    for match in LITERAL.finditer(text):
        piece = literal_value(match)
        if piece is not None and end >= 0 and LITERAL_GAP.fullmatch(text, end, match.start()):
            value += piece
        else:
            if value:
                runs.append((start, value))
            start, value = match.start(), piece or ""
        end = match.end() if piece is not None else -1
    if value:
        runs.append((start, value))
    return [(at, folded(run)) for at, run in runs if len(run) >= 3]


def folded(text: str) -> str:
    """Compatibility forms, accents and common look-alike letters folded."""
    text = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return text.translate(CONFUSABLE)

LFS_POINTER = re.compile(r"^version https://git-lfs\.github\.com/spec/", re.MULTILINE)
LFS_FILTER = re.compile(r"filter\s*=\s*lfs", re.IGNORECASE)


def views(data: bytes) -> list[tuple[str, str]]:
    result = [("", data.decode("latin-1"))]
    decoded = []
    try:
        decoded.append(("", data.decode("utf-8")))
    except UnicodeDecodeError:
        utf8 = False
    else:
        utf8 = True
    if b"\0" in data:
        result.append((" (NUL bytes removed)", data.replace(b"\0", b"").decode("latin-1")))
    if b"\0" in data or not utf8 or data.startswith((b"\xff\xfe", b"\xfe\xff")):
        for codec in ("utf-16-le", "utf-16-be"):
            for skip in (0, 1):
                decoded.append(
                    (f" ({codec})", data[skip:].decode(codec, errors="replace"))
                )
    for suffix, text in decoded:
        if suffix:
            result.append((suffix, text))
        normalized = folded(text)
        if normalized != text:
            result.append((f"{suffix} (folded)", normalized))
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
    # Base64 wrapped over several lines.
    unwrapped = re.sub(r"\s+", "", text)
    if unwrapped != text:
        for match in BASE64_RULE.finditer(unwrapped):
            if not BASE64_RULE.search(text):
                findings.append(
                    f"{label} (white space removed):1: name-base64: "
                    f"{excerpt(unwrapped, match.start(), match.end())}"
                )
                break
    for at, run in literal_runs(text):
        if WORD in run.lower() or INTERNAL_NAMES.search(run):
            line = text.count("\n", 0, at) + 1
            findings.append(f"{label}:{line}: name-literals: {run!r}")
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

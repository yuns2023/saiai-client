#!/usr/bin/env python3
"""Tests of release_manifest.py: RFC 8032 vectors, real minisign output (the
fixtures the program's own tests use), and keys generated at run time for
every refusal. The signer below exists only in this test."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Nothing is written next to the kernel's sources.
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("release_manifest", HERE / "release_manifest.py")
rm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rm)
FIXTURES = HERE.parent / "tests" / "fixtures" / "minisign"


def _scalar(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def _encode(point) -> bytes:
    x, y, z, _ = point
    inverse = pow(z, rm.P - 2, rm.P)
    x, y = x * inverse % rm.P, y * inverse % rm.P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


class TestKey:
    """An Ed25519 key (RFC 8032 signing) in minisign's formats."""

    def __init__(self, seed: bytes | None = None, key_id: bytes | None = None):
        self.seed = seed or os.urandom(32)
        self.key_id = key_id or os.urandom(8)
        self.scalar, self.prefix = _scalar(self.seed)
        self.public = _encode(rm._mul(self.scalar, rm._BASE))

    def raw_sign(self, message: bytes) -> bytes:
        r = int.from_bytes(hashlib.sha512(self.prefix + message).digest(), "little") % rm.L
        big_r = _encode(rm._mul(r, rm._BASE))
        h = int.from_bytes(hashlib.sha512(big_r + self.public + message).digest(), "little") % rm.L
        return big_r + ((r + h * self.scalar) % rm.L).to_bytes(32, "little")

    def public_text(self) -> str:
        return base64.b64encode(b"Ed" + self.key_id + self.public).decode()

    def sign(self, message: bytes, algorithm: bytes = b"Ed", key_id: bytes | None = None,
             comment: bytes = b"aitp-manifest test") -> bytes:
        signature = self.raw_sign(message)
        envelope = algorithm + (key_id or self.key_id) + signature
        return (
            b"untrusted comment: signature from minisign secret key\n"
            + base64.b64encode(envelope)
            + b"\ntrusted comment: " + comment + b"\n"
            + base64.b64encode(self.raw_sign(signature + comment)) + b"\n"
        )


def fixture_key(name: str) -> str:
    return (FIXTURES / name).read_text().splitlines()[1]


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for seed, public, message, signature in [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ]:
            key = TestKey(bytes.fromhex(seed))
            self.assertEqual(key.public.hex(), public)
            self.assertEqual(key.raw_sign(bytes.fromhex(message)).hex(), signature)
            self.assertTrue(rm.ed25519_verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)))
            self.assertFalse(rm.ed25519_verify(bytes.fromhex(public), b"x" + bytes.fromhex(message), bytes.fromhex(signature)))

    def test_non_canonical_and_small_order_inputs_are_refused(self):
        key = TestKey()
        signature = key.raw_sign(b"m")
        self.assertTrue(rm.ed25519_verify(key.public, b"m", signature))
        s = int.from_bytes(signature[32:], "little")
        self.assertFalse(rm.ed25519_verify(key.public, b"m", signature[:32] + (s + rm.L).to_bytes(32, "little")))
        identity = (1).to_bytes(32, "little")
        self.assertTrue(rm.is_small_order(rm.decode_point(identity)))
        self.assertFalse(rm.usable_public_key(identity))
        self.assertFalse(rm.usable_public_key(bytes(32)))  # order 4
        # y >= p is not canonical.
        self.assertIsNone(rm.decode_point((rm.P + 1).to_bytes(32, "little")))
        # x = 0 with the sign bit set.
        self.assertIsNone(rm.decode_point((1 | (1 << 255)).to_bytes(32, "little")))
        # The identity as public key with S = 0 and R = identity "verifies"
        # in a naive check; it is refused here.
        self.assertFalse(rm.ed25519_verify(identity, b"m", identity + bytes(32)))
        self.assertTrue(rm.usable_public_key(key.public))
        for placeholder in rm.PLACEHOLDER_KEYS:
            _, material = rm.parse_public_key(placeholder)
            self.assertIsNone(rm.decode_point(material), placeholder)


def noisy_padding(line: bytes) -> bytes:
    """The same 64 bytes with non-zero padding bits (not canonical)."""
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    data = line[:-2]
    value = alphabet.index(data[-1:])
    assert value & 0x0F == 0
    return data[:-1] + bytes([alphabet[value | 1]]) + b"=="


MANIFEST = b'{"assets":{},"distribution":"aitp","manifest_schema":1,"version":"9.9.9"}\n'


class SignatureTests(unittest.TestCase):
    def test_real_minisign_signatures(self):
        manifest = (FIXTURES / "manifest.json").read_bytes()
        primary, recovery = fixture_key("primary.pub"), fixture_key("recovery.pub")
        self.assertEqual(
            rm.verify_signature(manifest, (FIXTURES / "manifest.primary.minisig").read_bytes(), [primary, recovery]),
            (FIXTURES / "primary.pub").read_text().splitlines()[0].rsplit(" ", 1)[1],
        )
        self.assertEqual(
            rm.verify_signature(manifest, (FIXTURES / "manifest.recovery.minisig").read_bytes(), [primary, recovery]),
            (FIXTURES / "recovery.pub").read_text().splitlines()[0].rsplit(" ", 1)[1],
        )
        with self.assertRaisesRegex(rm.CheckError, "not trusted"):
            rm.verify_signature(manifest, (FIXTURES / "manifest.recovery.minisig").read_bytes(), [primary])
        with self.assertRaisesRegex(rm.CheckError, "minisign -S -l"):
            rm.verify_signature(manifest, (FIXTURES / "manifest.prehashed.minisig").read_bytes(), [primary])
        with self.assertRaisesRegex(rm.CheckError, "does not verify"):
            rm.verify_signature(manifest[:-1], (FIXTURES / "manifest.primary.minisig").read_bytes(), [primary])

    def test_runtime_keys_and_refusals(self):
        primary, recovery, stranger = TestKey(), TestKey(), TestKey()
        keys = [primary.public_text(), recovery.public_text()]
        signed = primary.sign(MANIFEST)
        rm.verify_signature(MANIFEST, signed, keys)
        rm.verify_signature(MANIFEST, recovery.sign(MANIFEST), keys)
        rm.verify_signature(MANIFEST, signed.replace(b"\n", b"\r\n"), keys)
        rm.verify_signature(MANIFEST, signed.replace(b"\n", b"\r\n", 2), keys)
        rm.verify_signature(MANIFEST, signed[:-1], keys)
        rm.verify_signature(MANIFEST, primary.sign(MANIFEST, comment=b""), keys)
        rm.verify_signature(MANIFEST, signed.replace(b"from minisign secret key", b"x"), keys)
        lines = signed.split(b"\n")
        cases = [
            (stranger.sign(MANIFEST), "not trusted"),
            (stranger.sign(MANIFEST, key_id=primary.key_id), "does not verify"),
            (primary.sign(MANIFEST, algorithm=b"ED"), "prehashed"),
            (primary.sign(MANIFEST, algorithm=b"Ex"), "Ed25519 format"),
            (signed.replace(b"aitp-manifest test", b"aitp-manifest tesT"), "trusted comment does not verify"),
            (b"\xef\xbb\xbf" + signed, "untrusted comment line"),
            (signed + b"\n", "5 lines"),
            (signed[:-1].replace(b"\n", b"\r"), "not LF or CRLF"),
            (signed.replace(b"trusted comment: a", b"trusted comment: \0a"), "NUL"),
            (signed.replace(lines[1], lines[1].rstrip(b"=")), "not canonical base64"),
            (signed.replace(lines[1], b" " + lines[1]), "not canonical base64"),
            (signed.replace(lines[1], lines[1][4:]), "not 74"),
            (signed.replace(b"trusted comment: ", b"untrusted comment: " + b"x" * 4096, 1), "larger than 4096"),
            # A CR that ends no line, and other control characters.
            (signed[:-1] + b"\r", "not LF or CRLF"),
            (signed[:-1] + b"\r\r\n", "not LF or CRLF"),
            (signed.replace(b"\n", b"\r\r\n", 1), "not LF or CRLF"),
            (signed.replace(b"trusted comment: a", b"trusted comment: \x1ba"), "control character"),
            (signed.replace(b"from minisign", b"from\x7fminisign"), "control character"),
            # Non-zero padding bits in the last character before "==".
            (signed.replace(lines[3], noisy_padding(lines[3])), "not canonical base64"),
            (signed.replace(lines[1], lines[1] + b"=="), "not canonical base64"),
        ]
        for variant, expected in cases:
            with self.assertRaisesRegex(rm.CheckError, expected):
                rm.verify_signature(MANIFEST, variant, keys)
        for index in range(len(MANIFEST)):
            changed = bytearray(MANIFEST)
            changed[index] ^= 1
            with self.assertRaises(rm.CheckError):
                rm.verify_signature(bytes(changed), signed, keys)
        for length in range(len(signed) - 1):
            with self.assertRaises(rm.CheckError):
                rm.verify_signature(MANIFEST, signed[:length], keys)


class ManifestTests(unittest.TestCase):
    def good(self, **change):
        manifest = {
            "manifest_schema": 1,
            "distribution": "aitp",
            "version": "1.2.3",
            "assets": {"aitp-linux-x86_64": {"sha256": "a" * 64, "size": 2 * 1024 * 1024}},
        }
        manifest.update(change)
        return json.dumps(manifest).encode()

    def test_rules_match_the_program(self):
        rm.parse_manifest(self.good(), "aitp")
        asset = '{"sha256":"' + "a" * 64 + '","size":2097152}'
        for text, expected in [
            (self.good(distribution="other"), "not 'aitp'"),
            (self.good(manifest_schema=2), "schema 2"),
            (self.good(manifest_schema=True), "schema True"),
            (self.good(manifest_schema=1.0), "schema 1.0"),
            (self.good(manifest_schema="1"), "schema '1'"),
            (self.good(version="v1.2.3"), "not X.Y.Z"),
            (self.good(version="01.2.3"), "not X.Y.Z"),
            (self.good(channel="beta"), "has fields"),
            (self.good(assets={"a": {"sha256": "A" * 64, "size": 2097152}}), "invalid sha256"),
            (self.good(assets={"a": {"sha256": "a" * 64, "size": True}}), "no size"),
            (self.good(assets={"a": {"sha256": "a" * 64, "size": 2097152.0}}), "no size"),
            (self.good(assets={"a": {"sha256": "a" * 64}}), "no size"),
            (self.good(assets={"a": {"sha256": "a" * 64, "size": 2097152, "url": "x"}}), "malformed"),
            (self.good().replace(b'"version"', b'"version": "1.2.4", "version"'), "repeats the field 'version'"),
            (self.good().replace(b'"version"', b'"version": "1.2.4", "vers\\u0069on"'), "repeats the field 'version'"),
            (('{"manifest_schema":1,"distribution":"aitp","version":"1.2.3","assets":{"a":' + asset + ',"a":' + asset + "}}").encode(), "repeats the field 'a'"),
            (b"\xef\xbb\xbf" + self.good(), "not JSON"),
        ]:
            with self.assertRaisesRegex(rm.CheckError, expected, msg=text):
                rm.parse_manifest(text, "aitp")


class BrandAndReleaseTests(unittest.TestCase):
    def test_key_lists_are_read_as_string_literals(self):
        a, b = TestKey(key_id=b"\xff" * 8), TestKey()
        # Base64 with "//" inside a literal, and comments between literals.
        text_a = a.public_text()
        self.assertIn("//", text_a)
        source = (
            'distribution: "aitp",\n'
            f'signing_keys: &[\n    // primary\n    "{text_a}", // trailing\n    "{b.public_text()}",\n],\n'
            '#[cfg(test)]\nsigning_keys: &["ignored"]'
        )
        self.assertEqual(rm.brand_keys(source), [text_a, b.public_text()])
        self.assertEqual(rm.brand_distribution(source), "aitp")
        with self.assertRaisesRegex(rm.CheckError, "repeats another key or key id"):
            rm.require_real_keys([a.public_text(), TestKey(key_id=a.key_id).public_text()])
        with self.assertRaisesRegex(rm.CheckError, "not a usable Ed25519 key"):
            rm.require_real_keys([base64.b64encode(b"Ed" + a.key_id + (1).to_bytes(32, "little")).decode()])

    def test_the_brand_declares_aitp_and_two_keys(self):
        self.assertEqual(rm.brand_distribution(), "aitp")
        keys = rm.brand_keys()
        self.assertEqual(len(keys), 2)
        if all(key in rm.PLACEHOLDER_KEYS for key in keys):
            with self.assertRaisesRegex(rm.CheckError, "still placeholders"):
                rm.require_real_keys(keys)
            result = subprocess.run(
                [sys.executable, "-I", str(HERE / "release_manifest.py"), "keys", "--require-real"],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, rm.PLACEHOLDER_EXIT, result)
            self.assertIn("still placeholders", result.stderr)
        else:
            rm.require_real_keys(keys)

    def test_generate_then_verify_before_upload(self):
        primary, recovery = TestKey(), TestKey()
        keys = [primary.public_text(), recovery.public_text()]
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            carried = b"\0".join(key.encode() for key in keys)
            for index, name in enumerate(rm.ASSETS):
                (dist / name).write_bytes(carried + bytes([index]) * (1024 * 1024 + index))
            result = subprocess.run(
                [sys.executable, "-I", str(HERE / "release_manifest.py"), "generate", "--dist", str(dist), "--version", "1.2.3"],
                capture_output=True, text=True, check=True,
            )
            manifest_path = dist / rm.MANIFEST_NAME
            manifest = manifest_path.read_bytes()
            digest = hashlib.sha256(manifest).hexdigest()
            self.assertIn(
                f'minisign -S -l -s aitp-release.key -p aitp-release.pub -m aitp-manifest.json '
                f'-x aitp-manifest.json.minisig -t "aitp-manifest 1.2.3 sha256:{digest}"',
                result.stdout,
            )
            self.assertEqual(json.loads(manifest)["distribution"], "aitp")
            self.assertTrue(manifest.endswith(b"}\n"))
            signature_path = dist / (rm.MANIFEST_NAME + rm.SIGNATURE_SUFFIX)
            signature_path.write_bytes(primary.sign(manifest))
            program = dist / "program"
            program.write_bytes(b"\0".join(key.encode() for key in keys))

            def check(**overrides):
                arguments = dict(
                    manifest_path=manifest_path, signature_path=signature_path, dist=dist,
                    artifacts=[program], version="1.2.3", keys=keys, distribution="aitp",
                )
                arguments.update(overrides)
                return rm.verify_release(**arguments)

            self.assertEqual(check(), rm.key_id_text(primary.key_id))
            signature_path.write_bytes(recovery.sign(manifest))
            self.assertEqual(check(), rm.key_id_text(recovery.key_id))
            cases = [
                (dict(keys=list(rm.PLACEHOLDER_KEYS)), "still placeholders"),
                (dict(version="1.2.4"), "the package is 1.2.4"),
                (dict(distribution="other"), "not 'other'"),
                (dict(assets=rm.ASSETS[:-1]), "the release has"),
                (dict(keys=[primary.public_text()]), "not trusted"),
            ]
            for overrides, expected in cases:
                with self.assertRaisesRegex(rm.CheckError, expected):
                    check(**overrides)
            # A program without the keys, or still with a placeholder.
            other = dist / "other-program"
            other.write_bytes(keys[0].encode())
            with self.assertRaisesRegex(rm.CheckError, "does not carry the trusted keys"):
                check(artifacts=[other])
            other.write_bytes(program.read_bytes() + rm.PLACEHOLDER_KEYS[0].encode())
            with self.assertRaisesRegex(rm.CheckError, "placeholder"):
                check(artifacts=[other])
            # A release asset (even one of six) without the keys, or with a
            # placeholder key, is refused although it matches the manifest:
            # the published programs themselves are checked.
            for content, expected in [
                (b"x" * (1024 * 1024 + 7), "does not carry the trusted keys"),
                (carried + rm.PLACEHOLDER_KEYS[1].encode() + b"x" * (1024 * 1024), "placeholder"),
            ]:
                (dist / rm.ASSETS[5]).write_bytes(content)
                rendered = rm.render_manifest(
                    "aitp", "1.2.3", {name: rm.file_metadata(dist / name) for name in rm.ASSETS}
                )
                manifest_path.write_bytes(rendered)
                signature_path.write_bytes(primary.sign(rendered))
                with self.assertRaisesRegex(rm.CheckError, expected):
                    check(artifacts=[])
            # A changed asset.
            (dist / rm.ASSETS[0]).write_bytes(b"x" * (1024 * 1024))
            with self.assertRaisesRegex(rm.CheckError, "does not match the manifest"):
                check()
            # A symbolic link instead of an asset.
            (dist / rm.ASSETS[0]).unlink()
            (dist / rm.ASSETS[0]).symlink_to(dist / rm.ASSETS[1])
            with self.assertRaisesRegex(rm.CheckError, "not a regular file"):
                check()
            # No signature.
            signature_path.unlink()
            with self.assertRaisesRegex(rm.CheckError, "signature is missing"):
                check()


if __name__ == "__main__":
    unittest.main()

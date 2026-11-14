//! Signed update manifests: real minisign output, and keys generated at
//! run time for every way a signature or manifest can be wrong.

use crate::update_signature::*;
use base64::Engine;
use ring::rand::SecureRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// A signing key generated for one test; its private half never leaves the
/// test process.
pub(crate) struct TestKey {
    pair: Ed25519KeyPair,
    pub(crate) id: [u8; 8],
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

impl TestKey {
    pub(crate) fn generate() -> Self {
        let random = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let mut id = [0_u8; 8];
        random.fill(&mut id).unwrap();
        Self {
            pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
            id,
        }
    }

    /// The minisign public key line.
    pub(crate) fn public_text(&self) -> String {
        self.public_text_with(*b"Ed", self.id)
    }

    fn public_text_with(&self, algorithm: [u8; 2], id: [u8; 8]) -> String {
        let mut raw = algorithm.to_vec();
        raw.extend(id);
        raw.extend(self.pair.public_key().as_ref());
        b64(&raw)
    }

    /// A minisign signature file over `message`, as `minisign -S -l` writes.
    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_with(message, *b"Ed", self.id, b"aitp-manifest test")
    }

    pub(crate) fn sign_with(
        &self,
        message: &[u8],
        algorithm: [u8; 2],
        id: [u8; 8],
        trusted_comment: &[u8],
    ) -> Vec<u8> {
        let signature = self.pair.sign(message);
        let mut envelope = algorithm.to_vec();
        envelope.extend(id);
        envelope.extend(signature.as_ref());
        let mut global = signature.as_ref().to_vec();
        global.extend(trusted_comment);
        let mut file = b"untrusted comment: signature from minisign secret key\n".to_vec();
        file.extend(b64(&envelope).bytes());
        file.extend(b"\ntrusted comment: ");
        file.extend(trusted_comment);
        file.push(b'\n');
        file.extend(b64(self.pair.sign(&global).as_ref()).bytes());
        file.push(b'\n');
        file
    }
}

/// Trusted keys for a `FixedUpdateSource` built in a test.
pub(crate) fn leak_keys(keys: &[&TestKey]) -> &'static [&'static str] {
    Vec::leak(
        keys.iter()
            .map(|key| &*String::leak(key.public_text()))
            .collect(),
    )
}

fn texts(keys: &[&TestKey]) -> Vec<String> {
    keys.iter().map(|key| key.public_text()).collect()
}

fn check(manifest: &[u8], signature: &[u8], keys: &[String]) -> anyhow::Result<String> {
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    verify(manifest, signature, &keys)
}

fn refused(manifest: &[u8], signature: &[u8], keys: &[String], expected: &str) {
    let error = check(manifest, signature, keys).unwrap_err();
    assert!(format!("{error:#}").contains(expected), "{error:#}");
}

const MANIFEST: &[u8] =
    br#"{"assets":{},"distribution":"ktest","manifest_schema":1,"version":"9.9.9"}
"#;

// Written by minisign 0.11 (`minisign -G -W`, then `-S -l` for the legacy
// format and plain `-S` for the prehashed one, verified with `minisign -V`);
// the secret keys were discarded. The recovery signature carries minisign's
// default trusted comment (with a tab).
const FIXTURE_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/minisign/manifest.json");
const FIXTURE_PRIMARY: &str = include_str!("../tests/fixtures/minisign/primary.pub");
const FIXTURE_RECOVERY: &str = include_str!("../tests/fixtures/minisign/recovery.pub");
const FIXTURE_SIGNED: &[u8] = include_bytes!("../tests/fixtures/minisign/manifest.primary.minisig");
const FIXTURE_RECOVERY_SIGNED: &[u8] =
    include_bytes!("../tests/fixtures/minisign/manifest.recovery.minisig");
const FIXTURE_PREHASHED: &[u8] =
    include_bytes!("../tests/fixtures/minisign/manifest.prehashed.minisig");

fn fixture_key(file: &str) -> String {
    let lines: Vec<_> = file.lines().collect();
    assert_eq!(lines.len(), 2, "{file}");
    assert!(lines[0].starts_with("untrusted comment: minisign public key "));
    lines[1].to_string()
}

#[test]
fn minisign_signatures_verify_and_name_their_key() {
    let primary = fixture_key(FIXTURE_PRIMARY);
    let recovery = fixture_key(FIXTURE_RECOVERY);
    let both = [primary.clone(), recovery.clone()];
    // minisign prints the key id in the public key's comment.
    let id = FIXTURE_PRIMARY
        .lines()
        .next()
        .unwrap()
        .rsplit(' ')
        .next()
        .unwrap();
    assert_eq!(check(FIXTURE_MANIFEST, FIXTURE_SIGNED, &both).unwrap(), id);
    assert_eq!(parse_public_key(&primary).unwrap().id_text(), id);
    let recovery_id = FIXTURE_RECOVERY
        .lines()
        .next()
        .unwrap()
        .rsplit(' ')
        .next()
        .unwrap();
    assert_eq!(
        check(FIXTURE_MANIFEST, FIXTURE_RECOVERY_SIGNED, &both).unwrap(),
        recovery_id
    );
    // The recovery key's signature means nothing to a program that trusts
    // only the primary key.
    refused(
        FIXTURE_MANIFEST,
        FIXTURE_RECOVERY_SIGNED,
        std::slice::from_ref(&primary),
        "which this program does not trust",
    );
    // minisign's default (prehashed) format is refused with a hint.
    refused(
        FIXTURE_MANIFEST,
        FIXTURE_PREHASHED,
        &both,
        "sign with `minisign -S -l`",
    );
    // A changed manifest no longer verifies.
    let mut changed = FIXTURE_MANIFEST.to_vec();
    changed.pop();
    refused(&changed, FIXTURE_SIGNED, &both, "does not verify");
    // The fixture manifest itself is a schema-1 manifest.
    let manifest = parse_manifest(FIXTURE_MANIFEST, "ktest").unwrap();
    assert_eq!(manifest.version, "9.9.9");
}

#[test]
fn a_signature_by_a_trusted_key_verifies_and_anything_else_is_refused() {
    let primary = TestKey::generate();
    let recovery = TestKey::generate();
    let stranger = TestKey::generate();
    let keys = texts(&[&primary, &recovery]);
    let signed = primary.sign(MANIFEST);
    check(MANIFEST, &signed, &keys).unwrap();
    // The recovery key is trusted as well.
    check(MANIFEST, &recovery.sign(MANIFEST), &keys).unwrap();
    // Unknown key id.
    refused(
        MANIFEST,
        &stranger.sign(MANIFEST),
        &keys,
        "which this program does not trust",
    );
    // A stranger's signature under a trusted key's id: only that key is
    // tried, and it does not verify.
    refused(
        MANIFEST,
        &stranger.sign_with(MANIFEST, *b"Ed", primary.id, b"x"),
        &keys,
        "does not verify with key",
    );
    // No key at all.
    refused(MANIFEST, &signed, &[], "at least one");
    // Every single changed byte of the manifest.
    for index in 0..MANIFEST.len() {
        let mut changed = MANIFEST.to_vec();
        changed[index] ^= 0x01;
        refused(&changed, &signed, &keys, "does not verify");
    }
    // One byte more or less.
    refused(
        &MANIFEST[..MANIFEST.len() - 1],
        &signed,
        &keys,
        "does not verify",
    );
    let mut longer = MANIFEST.to_vec();
    longer.push(b' ');
    refused(&longer, &signed, &keys, "does not verify");
}

#[test]
fn the_trusted_comment_is_signed_too() {
    let key = TestKey::generate();
    let keys = texts(&[&key]);
    let signed = String::from_utf8(key.sign(MANIFEST)).unwrap();
    let changed = signed.replace("aitp-manifest test", "aitp-manifest tesT");
    refused(
        MANIFEST,
        changed.as_bytes(),
        &keys,
        "trusted comment does not verify",
    );
    // A global signature of another comment.
    let other = String::from_utf8(key.sign_with(MANIFEST, *b"Ed", key.id, b"other")).unwrap();
    let mixed: Vec<&str> = signed
        .lines()
        .take(3)
        .chain(other.lines().skip(3))
        .collect();
    refused(
        MANIFEST,
        mixed.join("\n").as_bytes(),
        &keys,
        "trusted comment does not verify",
    );
    // An empty trusted comment, or one with trailing blanks, is fine when
    // signed as is.
    for comment in [&b""[..], b"x  ", b"timestamp:1\tfile:m.json"] {
        check(
            MANIFEST,
            &key.sign_with(MANIFEST, *b"Ed", key.id, comment),
            &keys,
        )
        .unwrap();
    }
    // The untrusted comment is not signed and may say anything.
    let relabeled = signed.replace(
        "untrusted comment: signature from minisign secret key",
        "untrusted comment: anything",
    );
    check(MANIFEST, relabeled.as_bytes(), &keys).unwrap();
}

#[test]
fn signature_files_follow_the_minisign_layout_exactly() {
    let key = TestKey::generate();
    let keys = texts(&[&key]);
    let signed = String::from_utf8(key.sign(MANIFEST)).unwrap();
    let lines: Vec<&str> = signed.lines().collect();
    assert_eq!(lines.len(), 4);
    // Accepted line endings: LF, CRLF, mixed, and no final line break.
    for variant in [
        lines.join("\n"),
        lines.join("\r\n") + "\r\n",
        format!("{}\r\n{}\n{}\r\n{}", lines[0], lines[1], lines[2], lines[3]),
    ] {
        check(MANIFEST, variant.as_bytes(), &keys).unwrap();
    }
    let padded_envelope = format!("{} ", lines[1]);
    let unpadded = lines[1].trim_end_matches('=');
    let url_safe = lines[1].replace('+', "-").replace('/', "_");
    let cases: Vec<(String, &str)> = vec![
        (format!("\u{feff}{signed}"), "untrusted comment line"),
        (format!("{signed}\n"), "5 lines"),
        (format!("{signed}extra\n"), "5 lines"),
        (lines[..3].join("\n"), "3 lines"),
        (String::new(), "1 lines"),
        (signed.replace('\n', "\r"), "not LF or CRLF"),
        (signed.replacen("\n", "\r\r\n", 1), "not LF or CRLF"),
        (
            signed.replacen("trusted comment: a", "trusted comment: \0a", 1),
            "NUL",
        ),
        (
            signed.replace(lines[1], &padded_envelope),
            "not canonical base64",
        ),
        (signed.replace(lines[1], unpadded), "not canonical base64"),
        (signed.replace(lines[1], &lines[1][4..]), "not 74"),
        (signed.replace(lines[3], &lines[3][4..]), "not 64"),
        (
            signed.replace(lines[1], &b64(&[1; 75])),
            "has 75 bytes, not 74",
        ),
        (
            signed.replace(lines[3], &b64(&[1; 63])),
            "has 63 bytes, not 64",
        ),
        (
            signed.replace("untrusted comment: ", "untrusted comment:"),
            "untrusted comment line",
        ),
        (
            signed.replace("trusted comment: aitp", "trusted-comment: aitp"),
            "no trusted comment line",
        ),
        // A comment longer than the limit.
        (
            signed.replace(
                "trusted comment: ",
                &format!("untrusted comment: {}", "x".repeat(4096)),
            ),
            "larger than 4096",
        ),
    ];
    // The URL-safe alphabet (when the line has a character that differs).
    if url_safe != lines[1] {
        refused(
            MANIFEST,
            signed.replace(lines[1], &url_safe).as_bytes(),
            &keys,
            "not canonical base64",
        );
    }
    for (variant, expected) in cases {
        refused(MANIFEST, variant.as_bytes(), &keys, expected);
    }
    // Truncated at every length.
    for length in 0..signed.len() - 1 {
        assert!(
            check(MANIFEST, &signed.as_bytes()[..length], &keys).is_err(),
            "{length}"
        );
    }
    // Non-zero trailing bits in the last base64 character.
    let last = lines[3].trim_end_matches('=');
    let mut bits = last.as_bytes().to_vec();
    let end = bits.len() - 1;
    bits[end] = if bits[end] == b'A' { b'B' } else { b'A' };
    let bits = String::from_utf8(bits).unwrap() + "==";
    if bits != lines[3] {
        let variant = signed.replace(lines[3], &bits);
        assert!(check(MANIFEST, variant.as_bytes(), &keys).is_err());
    }
}

#[test]
fn only_the_legacy_ed25519_algorithm_is_accepted() {
    let key = TestKey::generate();
    let keys = texts(&[&key]);
    refused(
        MANIFEST,
        &key.sign_with(MANIFEST, *b"ED", key.id, b"x"),
        &keys,
        "prehashed",
    );
    refused(
        MANIFEST,
        &key.sign_with(MANIFEST, *b"Ex", key.id, b"x"),
        &keys,
        "does not use minisign's Ed25519 format",
    );
}

/// `S + L` is the same signature in a non-canonical scalar: refused.
#[test]
fn a_non_canonical_signature_scalar_is_refused() {
    const ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let key = TestKey::generate();
    let keys = texts(&[&key]);
    let signed = String::from_utf8(key.sign(MANIFEST)).unwrap();
    let line = signed.lines().nth(1).unwrap();
    let mut envelope = base64::engine::general_purpose::STANDARD
        .decode(line)
        .unwrap();
    let mut carry = 0_u16;
    for (byte, order) in envelope[42..].iter_mut().zip(ORDER) {
        let sum = u16::from(*byte) + u16::from(order) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    let variant = signed.replace(line, &b64(&envelope));
    refused(MANIFEST, variant.as_bytes(), &keys, "does not verify");
}

#[test]
fn trusted_keys_must_be_distinct_minisign_ed25519_keys() {
    let one = TestKey::generate();
    let two = TestKey::generate();
    let ok = [one.public_text(), two.public_text()];
    parse_trusted_keys(&ok.iter().map(String::as_str).collect::<Vec<_>>()).unwrap();
    let same_id = two.public_text_with(*b"Ed", one.id);
    let same_key = one.public_text_with(*b"Ed", two.id);
    let prehashed = one.public_text_with(*b"ED", one.id);
    let short = one.public_text()[..52].to_string();
    for (keys, expected) in [
        (vec![], "at least one"),
        (vec![ok[0].clone(), same_id], "repeats"),
        (vec![ok[0].clone(), same_key], "repeats"),
        (vec![prehashed], "not a minisign Ed25519 key"),
        (vec![short], "not 42"),
        (vec![format!(" {}", ok[0])], "not canonical base64"),
    ] {
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        let error = parse_trusted_keys(&keys).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }
}

#[test]
fn manifests_name_schema_one_and_this_distribution() {
    let parse = |text: &str| parse_manifest(text.as_bytes(), "ktest");
    let asset = r#"{"sha256":"aa","size":1}"#;
    let good = format!(
        r#"{{"manifest_schema":1,"distribution":"ktest","version":"9.9.9","assets":{{"a":{asset}}}}}"#
    );
    let manifest = parse(&good).unwrap();
    assert_eq!(manifest.assets["a"].size, Some(1));
    for (text, expected) in [
        (good.replace("\"ktest\"", "\"other\""), "not \"ktest\""),
        (good.replace("\"ktest\"", "\"KTEST\""), "not \"ktest\""),
        (good.replace("\"ktest\"", "\"ktest \""), "not \"ktest\""),
        (
            good.replace(r#""distribution":"ktest","#, ""),
            "missing field `distribution`",
        ),
        (
            good.replace(r#""distribution":"ktest""#, r#""distribution":null"#),
            "invalid type",
        ),
        (
            good.replace(r#""manifest_schema":1,"#, ""),
            "missing field `manifest_schema`",
        ),
        (
            good.replace(r#""manifest_schema":1"#, r#""manifest_schema":2"#),
            "schema 2",
        ),
        (
            good.replace(r#""manifest_schema":1"#, r#""manifest_schema":true"#),
            "invalid type",
        ),
        (
            good.replace(r#""manifest_schema":1"#, r#""manifest_schema":1.0"#),
            "invalid type",
        ),
        (
            good.replace(r#""manifest_schema":1"#, r#""manifest_schema":"1""#),
            "invalid type",
        ),
        (
            good.replace(
                r#""version":"9.9.9""#,
                r#""version":"9.9.9","version":"9.9.8""#,
            ),
            "duplicate field `version`",
        ),
        (
            good.replace(
                r#""manifest_schema":1"#,
                r#""manifest_schema":1,"manifest_schema":1"#,
            ),
            "duplicate field",
        ),
        (
            good.replace(
                r#""assets":{"a":"#,
                &format!(r#""assets":{{"a":{asset},"a":"#),
            ),
            "duplicate asset \"a\"",
        ),
        (
            good.replace(r#""size":1"#, r#""size":1,"size":2"#),
            "duplicate field `size`",
        ),
        (good.replace(r#""size":1"#, r#""size":-1"#), "invalid value"),
        (good.replace(r#""size":1"#, r#""size":1.5"#), "invalid type"),
        (
            good.replace(r#""version""#, r#""channel":"x","version""#),
            "unknown field `channel`",
        ),
        (
            good.replace(r#""size":1"#, r#""size":1,"url":"x""#),
            "unknown field `url`",
        ),
        (format!("\u{feff}{good}"), "expected value"),
        (format!("{good} {{}}"), "trailing characters"),
    ] {
        let error = parse(&text).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{text}: {error:#}");
    }
    assert!(is_sha256_hex(&"a".repeat(64)));
    for bad in [
        "A".repeat(64),
        "a".repeat(63),
        format!(" {}", "a".repeat(64)),
        "g".repeat(64),
    ] {
        assert!(!is_sha256_hex(&bad), "{bad}");
    }
}

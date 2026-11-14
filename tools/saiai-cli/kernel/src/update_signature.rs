//! Signed update manifests of a fixed update source.
//!
//! The manifest is signed offline in minisign's legacy format (algorithm
//! `Ed`: plain Ed25519 over the manifest's exact bytes), so a maintainer
//! signs with the stock tool (`minisign -S -l …`) and checks the result with
//! `minisign -V`. The default prehashed format (`ED`, BLAKE2b-512 first) is
//! refused with a hint; it needs a hash this program does not carry.
//!
//! Wire formats (minisign):
//! - public key: base64 (56 characters) of `Ed` ‖ key id (8) ‖ Ed25519
//!   public key (32), the second line of a `.pub` file;
//! - signature file: four lines — `untrusted comment: …`, base64 (100) of
//!   algorithm (2) ‖ key id (8) ‖ signature (64), `trusted comment: …`,
//!   base64 (88) of the global signature, an Ed25519 signature over
//!   signature (64) ‖ trusted comment bytes.
//!
//! Only after the signature verifies is the manifest parsed: a manifest of
//! schema 1 that names this distribution, one release version, and every
//! asset's SHA-256 and size.

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Suffix of the signature file next to the manifest (minisign's default).
pub(crate) const SIGNATURE_SUFFIX: &str = ".minisig";
/// Upper bound of a signature file (two short comment lines and two
/// base64 lines are well under 1 KiB).
pub(crate) const SIGNATURE_LIMIT: u64 = 4096;
/// The manifest schema this program reads.
pub(crate) const MANIFEST_SCHEMA: u32 = 1;

const ALGORITHM: &[u8; 2] = b"Ed";
const PREHASHED_ALGORITHM: &[u8; 2] = b"ED";
const UNTRUSTED_PREFIX: &[u8] = b"untrusted comment: ";
const TRUSTED_PREFIX: &[u8] = b"trusted comment: ";

/// A trusted update signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PublicKey {
    id: [u8; 8],
    key: [u8; 32],
}

impl PublicKey {
    /// The key id as minisign prints it (`minisign public key <ID>`).
    pub(crate) fn id_text(&self) -> String {
        key_id_text(&self.id)
    }
}

/// minisign prints a key id as the little-endian 64-bit number in upper-case
/// hexadecimal, without leading zeros.
fn key_id_text(id: &[u8; 8]) -> String {
    format!("{:X}", u64::from_le_bytes(*id))
}

/// Strict standard base64 (padding and trailing bits canonical, no
/// whitespace) of exactly `N` bytes.
fn decode_exact<const N: usize>(text: &[u8], what: &str) -> Result<[u8; N]> {
    let engine = &base64::engine::general_purpose::STANDARD;
    let bytes = engine
        .decode(text)
        .ok()
        .filter(|bytes| engine.encode(bytes).as_bytes() == text)
        .with_context(|| format!("{what} is not canonical base64"))?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("{what} has {} bytes, not {N}", bytes.len()))
}

/// A public key from its minisign text (the base64 line of a `.pub` file).
pub(crate) fn parse_public_key(text: &str) -> Result<PublicKey> {
    let raw = decode_exact::<42>(text.as_bytes(), "the update signing key")?;
    if &raw[..2] != ALGORITHM {
        bail!("the update signing key is not a minisign Ed25519 key");
    }
    let key = PublicKey {
        id: raw[2..10].try_into().expect("8 bytes"),
        key: raw[10..].try_into().expect("32 bytes"),
    };
    if is_small_order_encoding(&key.key) {
        bail!(
            "update signing key {} is a small-order point, not a usable Ed25519 key",
            key.id_text()
        );
    }
    Ok(key)
}

/// The encodings of the points of order 1, 2, 4 and 8 (and the
/// non-canonical encodings of y = 0 and y = 1), sign bit ignored: libsodium's
/// list. With such a key, signatures can be made without its secret.
fn is_small_order_encoding(key: &[u8; 32]) -> bool {
    const SMALL_ORDER: [[u8; 32]; 7] = [
        [0; 32],
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ],
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ],
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];
    SMALL_ORDER
        .iter()
        .any(|small| small[..31] == key[..31] && small[31] == key[31] & 0x7f)
}

/// A brand's trusted keys: at least one, valid, with distinct key ids and
/// distinct key material.
pub(crate) fn parse_trusted_keys(texts: &[&str]) -> Result<Vec<PublicKey>> {
    if texts.is_empty() {
        bail!("a fixed update source needs at least one update signing key");
    }
    let mut keys: Vec<PublicKey> = Vec::with_capacity(texts.len());
    for text in texts {
        let key = parse_public_key(text).with_context(|| format!("{text:?}"))?;
        if keys
            .iter()
            .any(|other| other.id == key.id || other.key == key.key)
        {
            bail!(
                "update signing key {} repeats another key's id or key",
                key.id_text()
            );
        }
        keys.push(key);
    }
    Ok(keys)
}

struct SignatureFile<'a> {
    algorithm: [u8; 2],
    key_id: [u8; 8],
    signature: [u8; 64],
    trusted_comment: &'a [u8],
    global_signature: [u8; 64],
}

/// The four lines of a minisign signature file, each ending in LF or CRLF
/// (the last one may end without). Anything else is refused: a fifth or
/// empty line, a CR that does not end a line, NUL or another control
/// character (TAB aside, which minisign's default comment uses), a byte
/// order mark (the first line then does not start with the comment prefix).
fn parse_signature_file(bytes: &[u8]) -> Result<SignatureFile<'_>> {
    if bytes.len() as u64 > SIGNATURE_LIMIT {
        bail!("the signature file is larger than {SIGNATURE_LIMIT} bytes");
    }
    if bytes.contains(&0) {
        bail!("the signature file contains a NUL byte");
    }
    // Each LF may be preceded by one CR, which belongs to the line break.
    let body = bytes
        .strip_suffix(b"\n")
        .map(|rest| rest.strip_suffix(b"\r").unwrap_or(rest))
        .unwrap_or(bytes);
    let mut lines: Vec<&[u8]> = body.split(|byte| *byte == b'\n').collect();
    let last = lines.len() - 1;
    for line in &mut lines[..last] {
        *line = line.strip_suffix(b"\r").unwrap_or(line);
    }
    if lines.iter().any(|line| line.contains(&b'\r')) {
        bail!("the signature file has a line break that is not LF or CRLF");
    }
    if lines.iter().any(|line| {
        line.iter()
            .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    }) {
        bail!("the signature file contains a control character");
    }
    let [untrusted, envelope, trusted, global] = lines.as_slice() else {
        bail!(
            "the signature file has {} lines, a minisign signature has 4",
            lines.len()
        );
    };
    if !untrusted.starts_with(UNTRUSTED_PREFIX) {
        bail!("the signature file does not start with an untrusted comment line");
    }
    let envelope = decode_exact::<74>(envelope, "the signature line")?;
    let Some(trusted_comment) = trusted.strip_prefix(TRUSTED_PREFIX) else {
        bail!("the signature file has no trusted comment line");
    };
    Ok(SignatureFile {
        algorithm: envelope[..2].try_into().expect("2 bytes"),
        key_id: envelope[2..10].try_into().expect("8 bytes"),
        signature: envelope[10..].try_into().expect("64 bytes"),
        trusted_comment,
        global_signature: decode_exact::<64>(global, "the trusted comment signature")?,
    })
}

fn ed25519_verifies(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(message, signature)
        .is_ok()
}

/// Verifies `signature_file` over the exact bytes of `manifest` with one of
/// `trusted` (the key its id names; no other key is tried), including the
/// trusted comment's signature. Returns the signing key's id.
pub(crate) fn verify(manifest: &[u8], signature_file: &[u8], trusted: &[&str]) -> Result<String> {
    let keys = parse_trusted_keys(trusted)?;
    let file = parse_signature_file(signature_file)?;
    if &file.algorithm == PREHASHED_ALGORITHM {
        bail!(
            "the manifest is signed in minisign's prehashed format; only the legacy Ed25519 format is accepted (sign with `minisign -S -l`)"
        );
    }
    if &file.algorithm != ALGORITHM {
        bail!("the signature does not use minisign's Ed25519 format");
    }
    let Some(key) = keys.iter().find(|key| key.id == file.key_id) else {
        bail!(
            "the manifest is signed by key {}, which this program does not trust (trusted: {})",
            key_id_text(&file.key_id),
            keys.iter()
                .map(PublicKey::id_text)
                .collect::<Vec<_>>()
                .join(", ")
        );
    };
    if !ed25519_verifies(&key.key, manifest, &file.signature) {
        bail!(
            "the manifest signature does not verify with key {}",
            key.id_text()
        );
    }
    let mut global = Vec::with_capacity(64 + file.trusted_comment.len());
    global.extend_from_slice(&file.signature);
    global.extend_from_slice(file.trusted_comment);
    if !ed25519_verifies(&key.key, &global, &file.global_signature) {
        bail!(
            "the signature's trusted comment does not verify with key {}",
            key.id_text()
        );
    }
    Ok(key.id_text())
}

/// A signed fixed-source manifest. Unknown and repeated fields are refused
/// (a later format raises `manifest_schema`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixedManifest {
    pub(crate) manifest_schema: u32,
    pub(crate) distribution: String,
    pub(crate) version: String,
    #[serde(deserialize_with = "unique_assets")]
    pub(crate) assets: BTreeMap<String, FixedManifestAsset>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixedManifestAsset {
    pub(crate) sha256: String,
    pub(crate) size: Option<u64>,
}

/// The asset map, refusing a name that appears twice (a plain map would
/// keep the last one).
fn unique_assets<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, FixedManifestAsset>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, FixedManifestAsset>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a map of release assets")
        }

        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut assets = BTreeMap::new();
            while let Some((name, asset)) = map.next_entry::<String, FixedManifestAsset>()? {
                if assets.contains_key(&name) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate asset {name:?}"
                    )));
                }
                assets.insert(name, asset);
            }
            Ok(assets)
        }
    }
    deserializer.deserialize_map(Visitor)
}

/// Parses a verified manifest and checks its schema and distribution.
pub(crate) fn parse_manifest(bytes: &[u8], distribution: &str) -> Result<FixedManifest> {
    let manifest = serde_json::from_slice::<FixedManifest>(bytes)?;
    if manifest.manifest_schema != MANIFEST_SCHEMA {
        bail!(
            "the manifest has schema {}, this program reads schema {MANIFEST_SCHEMA}",
            manifest.manifest_schema
        );
    }
    if manifest.distribution != distribution {
        bail!(
            "the manifest is for distribution {:?}, not {distribution:?}",
            manifest.distribution
        );
    }
    Ok(manifest)
}

/// Exactly 64 lower-case hexadecimal digits.
pub(crate) fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

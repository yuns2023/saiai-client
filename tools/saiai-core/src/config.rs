use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;
use std::str::FromStr;
use url::Url;

use crate::fsutil::is_portable_reference_component;
use crate::{CredentialRef, Error, Product, Result, SecretString};

pub const CONFIG_SCHEMA_VERSION: u32 = 2;
pub const MAX_GATEWAY_URL_BYTES: usize = 4096;

/// Opaque, path-safe reference to one product's fully staged generation.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct GenerationRef(String);

impl GenerationRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid_length = !value.is_empty() && value.len() <= 64;
        let mut chars = value.chars();
        let valid_start = chars
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric());
        let valid_rest = chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        });
        if !valid_length
            || !valid_start
            || !valid_rest
            || matches!(value.as_str(), "." | "..")
            || !is_portable_reference_component(&value)
        {
            return Err(Error::InvalidConfig(
                "generation must use 1-64 portable path-safe ASCII characters".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GenerationRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("GenerationRef")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for GenerationRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for GenerationRef {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GenerationRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A validated and normalized SAIAI gateway base URL.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct GatewayUrl(Url);

impl GatewayUrl {
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(Error::InvalidGatewayUrl("URL is empty".into()));
        }
        if input.len() > MAX_GATEWAY_URL_BYTES {
            return Err(Error::InvalidGatewayUrl(format!(
                "URL exceeds the {MAX_GATEWAY_URL_BYTES}-byte limit"
            )));
        }
        if input.trim() != input {
            return Err(Error::InvalidGatewayUrl(
                "leading or trailing whitespace is not allowed".into(),
            ));
        }
        if input.chars().any(char::is_whitespace) {
            return Err(Error::InvalidGatewayUrl("whitespace is not allowed".into()));
        }

        let mut url = Url::parse(input)
            .map_err(|error| Error::InvalidGatewayUrl(format!("could not parse URL: {error}")))?;

        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::InvalidGatewayUrl(
                "scheme must be http or https".into(),
            ));
        }
        if url.host_str().is_none() {
            return Err(Error::InvalidGatewayUrl("host is required".into()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::InvalidGatewayUrl(
                "embedded credentials are not allowed".into(),
            ));
        }
        if url.query().is_some() {
            return Err(Error::InvalidGatewayUrl(
                "query parameters are not allowed".into(),
            ));
        }
        if url.fragment().is_some() {
            return Err(Error::InvalidGatewayUrl("fragments are not allowed".into()));
        }

        let normalized_path = if url.path() == "/" {
            "/".to_owned()
        } else {
            url.path().trim_end_matches('/').to_owned()
        };
        url.set_path(&normalized_path);

        Ok(Self(url))
    }

    pub fn as_url(&self) -> &Url {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn reject_credential_url_component(&self, credential: &SecretString) -> Result<()> {
        let credential_text = credential.expose_secret();
        let credential = credential_text.as_bytes();
        let matches_host_label = self.0.host_str().is_some_and(|host| {
            host.split('.')
                .any(|label| label.eq_ignore_ascii_case(credential_text))
        });
        let matches_segment = self
            .0
            .path_segments()
            .is_some_and(|mut segments| segments.any(|segment| path_value_eq(segment, credential)));
        let path = self.0.path();
        let matches_whole_path = path_value_eq(path, credential)
            || path_value_eq(path.strip_prefix('/').unwrap_or(path), credential);
        if matches_host_label || matches_segment || matches_whole_path {
            return Err(Error::InvalidGatewayUrl(
                "Gateway URL must not contain the API key as a host label or path segment".into(),
            ));
        }
        Ok(())
    }
}

fn path_value_eq(value: &str, expected: &[u8]) -> bool {
    value.as_bytes() == expected || percent_decoded_eq(value, expected)
}

fn percent_decoded_eq(value: &str, expected: &[u8]) -> bool {
    let bytes = value.as_bytes();
    let mut value_index = 0;
    let mut expected_index = 0;

    while value_index < bytes.len() {
        let (decoded, consumed) = if bytes[value_index] == b'%' && value_index + 2 < bytes.len() {
            match (
                hex_value(bytes[value_index + 1]),
                hex_value(bytes[value_index + 2]),
            ) {
                (Some(high), Some(low)) => ((high << 4) | low, 3),
                _ => (bytes[value_index], 1),
            }
        } else {
            (bytes[value_index], 1)
        };
        if expected.get(expected_index) != Some(&decoded) {
            return false;
        }
        value_index += consumed;
        expected_index += 1;
    }

    expected_index == expected.len()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

impl fmt::Debug for GatewayUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("GatewayUrl")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for GatewayUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for GatewayUrl {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for GatewayUrl {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for GatewayUrl {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GatewayUrl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

/// Non-secret state for one independently provisioned product.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductConfig {
    credential_ref: CredentialRef,
    active_generation: GenerationRef,
}

impl ProductConfig {
    pub fn new(credential_ref: CredentialRef, active_generation: GenerationRef) -> Self {
        Self {
            credential_ref,
            active_generation,
        }
    }

    pub fn credential_ref(&self) -> &CredentialRef {
        &self.credential_ref
    }

    pub fn active_generation(&self) -> &GenerationRef {
        &self.active_generation
    }
}

/// Optional product entries in the shared installation configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductEntries {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claude: Option<ProductConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    codex: Option<ProductConfig>,
}

impl ProductEntries {
    pub fn get(&self, product: Product) -> Option<&ProductConfig> {
        match product {
            Product::Claude => self.claude.as_ref(),
            Product::Codex => self.codex.as_ref(),
        }
    }

    pub fn contains(&self, product: Product) -> bool {
        self.get(product).is_some()
    }

    pub fn is_empty(&self) -> bool {
        self.claude.is_none() && self.codex.is_none()
    }

    pub fn configured_products(&self) -> impl Iterator<Item = Product> + '_ {
        Product::ALL
            .into_iter()
            .filter(|product| self.contains(*product))
    }

    pub(crate) fn insert(&mut self, product: Product, config: ProductConfig) {
        match product {
            Product::Claude => self.claude = Some(config),
            Product::Codex => self.codex = Some(config),
        }
    }

    pub(crate) fn remove(&mut self, product: Product) -> Option<ProductConfig> {
        match product {
            Product::Claude => self.claude.take(),
            Product::Codex => self.codex.take(),
        }
    }
}

/// Version-two non-secret configuration with independent product entries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfigV2 {
    schema_version: u32,
    base_url: GatewayUrl,
    products: ProductEntries,
}

impl ConfigV2 {
    pub fn new(base_url: GatewayUrl, product: Product, product_config: ProductConfig) -> Self {
        let mut products = ProductEntries::default();
        products.insert(product, product_config);
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            base_url,
            products,
        }
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn base_url(&self) -> &GatewayUrl {
        &self.base_url
    }

    pub fn products(&self) -> &ProductEntries {
        &self.products
    }

    pub fn product(&self, product: Product) -> Option<&ProductConfig> {
        self.products.get(product)
    }

    pub(crate) fn insert_product(&mut self, product: Product, config: ProductConfig) {
        self.products.insert(product, config);
    }

    pub(crate) fn replace_base_url(&mut self, base_url: GatewayUrl) {
        self.base_url = base_url;
    }

    pub(crate) fn remove_product(&mut self, product: Product) -> Option<ProductConfig> {
        self.products.remove(product)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigV2Wire {
    schema_version: u32,
    base_url: GatewayUrl,
    products: ProductEntries,
}

impl<'de> Deserialize<'de> for ConfigV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ConfigV2Wire::deserialize(deserializer)?;
        if wire.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(de::Error::custom(format!(
                "unsupported schema_version {}; expected {}. This client does not migrate older V2 state; run `saiai revoke --all` to reset it",
                wire.schema_version, CONFIG_SCHEMA_VERSION
            )));
        }
        if wire.products.is_empty() {
            return Err(de::Error::custom(
                "products must contain at least one configured product",
            ));
        }
        if let (Some(claude), Some(codex)) = (
            wire.products.get(Product::Claude),
            wire.products.get(Product::Codex),
        ) {
            if claude
                .credential_ref()
                .as_str()
                .eq_ignore_ascii_case(codex.credential_ref().as_str())
            {
                return Err(de::Error::custom(
                    "Claude and Codex must not share a credential_ref",
                ));
            }
            if claude
                .active_generation()
                .as_str()
                .eq_ignore_ascii_case(codex.active_generation().as_str())
            {
                return Err(de::Error::custom(
                    "Claude and Codex must not share an active_generation",
                ));
            }
        }
        Ok(Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            base_url: wire.base_url,
            products: wire.products,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_url_accepts_http_https_and_normalizes_trailing_slashes() {
        assert_eq!(
            GatewayUrl::parse("https://api.example.test///")
                .unwrap()
                .as_str(),
            "https://api.example.test/"
        );
        assert_eq!(
            GatewayUrl::parse("http://127.0.0.1:18080/gateway///")
                .unwrap()
                .as_str(),
            "http://127.0.0.1:18080/gateway"
        );
    }

    #[test]
    fn gateway_url_rejects_ambiguous_or_unsafe_shapes() {
        for value in [
            "",
            " https://api.example.test",
            "ftp://api.example.test",
            "https://user:secret@api.example.test",
            "https://api.example.test?key=value",
            "https://api.example.test/#fragment",
            "not a url",
        ] {
            assert!(GatewayUrl::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn gateway_url_length_limit_does_not_reflect_oversized_input() {
        let secret = "sk-never-reflect-oversized-url";
        let oversized = format!(
            "https://api.example.test/{}{}",
            "a".repeat(MAX_GATEWAY_URL_BYTES),
            secret
        );
        let error = GatewayUrl::parse(&oversized).unwrap_err();
        assert!(!format!("{error}").contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    #[test]
    fn config_v2_has_independent_optional_product_entries() {
        let valid = r#"{
            "schema_version": 2,
            "base_url": "https://api.example.test/",
            "products": {
                "claude": {
                    "credential_ref": "claude-credential",
                    "active_generation": "gen-claude"
                }
            }
        }"#;
        let parsed: ConfigV2 = serde_json::from_str(valid).unwrap();
        assert_eq!(parsed.schema_version(), 2);
        assert!(parsed.product(Product::Claude).is_some());
        assert!(parsed.product(Product::Codex).is_none());

        let old = valid.replace("\"schema_version\": 2", "\"schema_version\": 1");
        let error = serde_json::from_str::<ConfigV2>(&old).unwrap_err();
        assert!(error.to_string().contains("does not migrate"));

        let empty = valid.replace(
            r#""claude": {
                    "credential_ref": "claude-credential",
                    "active_generation": "gen-claude"
                }"#,
            "",
        );
        assert!(serde_json::from_str::<ConfigV2>(&empty).is_err());

        let unknown = valid.replace(
            "\n            }\n        }",
            "\n            }, \"legacy\": true\n        }",
        );
        assert!(serde_json::from_str::<ConfigV2>(&unknown).is_err());
    }

    #[test]
    fn generation_references_cannot_escape_the_data_root() {
        for invalid in [
            "",
            ".",
            "..",
            "../other",
            "/absolute",
            "has space",
            "generation.",
            "CON",
            "nul.txt",
            "COM1.log",
        ] {
            assert!(GenerationRef::new(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn two_products_cannot_share_credential_or_generation_references() {
        let base = r#"{
            "schema_version": 2,
            "base_url": "https://api.example.test/",
            "products": {
                "claude": {
                    "credential_ref": "claude-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "active_generation": "gen-claude-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                },
                "codex": {
                    "credential_ref": "codex-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "active_generation": "gen-codex-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                }
            }
        }"#;
        let shared_credential = base.replace(
            "codex-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "claude-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert!(serde_json::from_str::<ConfigV2>(&shared_credential).is_err());
        assert!(
            serde_json::from_str::<ConfigV2>(&shared_credential.replacen(
                "claude-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "CLAUDE-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                1,
            ))
            .is_err()
        );

        let shared_generation = base.replace(
            "gen-codex-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "gen-claude-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert!(serde_json::from_str::<ConfigV2>(&shared_generation).is_err());
    }
}

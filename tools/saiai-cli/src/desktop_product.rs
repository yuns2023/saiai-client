use anyhow::{Result, bail};

/// Product-level Desktop identity. The process/profile/proxy lifecycle is
/// shared, while each product gets its own adapter as it is implemented.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DesktopProduct {
    Codex,
    ChatGPT,
    Claude,
    Gemini,
}

impl DesktopProduct {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "codex" => Ok(Self::Codex),
            "chatgpt" | "openai" => Ok(Self::ChatGPT),
            "claude" | "anthropic" => Ok(Self::Claude),
            "gemini" | "google" => Ok(Self::Gemini),
            other => {
                bail!("unknown Desktop product {other}; expected codex, chatgpt, claude, or gemini")
            }
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ChatGPT => "ChatGPT",
            Self::Claude => "Claude",
            Self::Gemini => "Gemini",
        }
    }

    pub const fn has_adapter(self) -> bool {
        // The official Desktop executable remains branded ChatGPT, but the
        // SAIAI Desktop contract currently covers only its Codex surface.
        // Ordinary Chat has a distinct account/history/settings protocol and
        // must not be implied by a working Codex launcher.
        matches!(self, Self::Codex)
    }
}

#[cfg(test)]
mod tests {
    use super::DesktopProduct;

    #[test]
    fn only_codex_has_a_supported_desktop_adapter() {
        assert!(DesktopProduct::Codex.has_adapter());
        assert!(!DesktopProduct::ChatGPT.has_adapter());
        assert!(!DesktopProduct::Claude.has_adapter());
        assert!(!DesktopProduct::Gemini.has_adapter());
    }
}

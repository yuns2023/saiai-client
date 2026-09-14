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
        matches!(self, Self::Codex | Self::ChatGPT)
    }
}

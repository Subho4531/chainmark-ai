use std::sync::LazyLock;
use regex::Regex;
use chainmark_vault::{TokenVault, TOKEN_PREFIX, TOKEN_PATTERN};

static TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(TOKEN_PATTERN).expect("valid token regex")
});

const MAX_TOKEN_LENGTH: usize = 128;

pub struct StreamTokenRestorer {
    vault: TokenVault,
    session_id: String,
    buffer: String,
    pub unresolved: usize,
}

impl StreamTokenRestorer {
    pub fn new(vault: TokenVault, session_id: impl Into<String>) -> Self {
        Self {
            vault,
            session_id: session_id.into(),
            buffer: String::new(),
            unresolved: 0,
        }
    }

    fn is_token_prefix(&self, candidate: &str) -> bool {
        if candidate.is_empty() {
            return false;
        }
        TOKEN_PREFIX.starts_with(candidate) || candidate.starts_with(TOKEN_PREFIX)
    }

    pub fn push(&mut self, text: &str) -> String {
        if !text.is_empty() {
            self.buffer.push_str(text);
        }

        let mut out = String::new();

        loop {
            if let Some(m) = TOKEN_RE.find(&self.buffer) {
                let start = m.start();
                let end = m.end();
                out.push_str(&self.buffer[..start]);

                let token_str = m.as_str();
                match self.vault.detokenize_value(token_str, &self.session_id) {
                    Some(plain) => out.push_str(&plain),
                    None => {
                        self.unresolved += 1;
                        out.push_str(token_str);
                    }
                }

                self.buffer = self.buffer[end..].to_string();
                continue;
            }

            match self.buffer.rfind('[') {
                None => {
                    out.push_str(&self.buffer);
                    self.buffer.clear();
                }
                Some(bracket) => {
                    let suffix = &self.buffer[bracket..];
                    if suffix.len() <= MAX_TOKEN_LENGTH && self.is_token_prefix(suffix) {
                        out.push_str(&self.buffer[..bracket]);
                        self.buffer = suffix.to_string();
                    } else {
                        out.push_str(&self.buffer);
                        self.buffer.clear();
                    }
                }
            }
            break;
        }

        out
    }

    pub fn flush(&mut self) -> String {
        let (restored, unres) = self.vault.detokenize_text_strict(&self.buffer, &self.session_id);
        self.unresolved += unres;
        self.buffer.clear();
        restored
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainmark_types::EntityType;

    #[test]
    fn test_stream_restorer_normal_brackets_instant_release() {
        let vault = TokenVault::new([1u8; 32]);
        let mut restorer = StreamTokenRestorer::new(vault, "stream_test");

        // "[1, 2, 3]" is not a token prefix, so once the bracket content diverges it releases
        assert_eq!(restorer.push("["), "");
        assert_eq!(restorer.push("1, 2, 3]"), "[1, 2, 3]");
    }

    #[test]
    fn test_stream_restorer_reassembles_split_token() {
        let vault = TokenVault::new([1u8; 32]);
        let session = "stream_reassemble";
        let raw = "ABCPE1234F";
        let token = vault.tokenize_value(EntityType::Pan, raw, session).unwrap();

        let mut restorer = StreamTokenRestorer::new(vault, session);
        let split_idx = token.len() / 2;
        let part1 = &token[..split_idx];
        let part2 = &token[split_idx..];

        let out1 = restorer.push(&format!("The PAN is {}", part1));
        assert_eq!(out1, "The PAN is ");

        let out2 = restorer.push(&format!("{} verified.", part2));
        assert_eq!(out2, "ABCPE1234F verified.");

        let tail = restorer.flush();
        assert_eq!(tail, "");
    }
}

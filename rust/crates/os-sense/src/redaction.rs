const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "auth",
    "authorization",
];

pub(crate) fn redact_sensitive_text(input: &str, max_chars: usize) -> String {
    let mut mask_next = false;
    let mut tokens = Vec::new();

    for token in input.split_whitespace() {
        if mask_next {
            tokens.push("[REDACTED]".to_string());
            mask_next = false;
            continue;
        }

        let lower = token.to_ascii_lowercase();
        if let Some((idx, sep)) = lower
            .find('=')
            .map(|idx| (idx, '='))
            .or_else(|| lower.find(':').map(|idx| (idx, ':')))
        {
            let key = lower[..idx]
                .trim_start_matches('-')
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_');
            if is_sensitive_key(key) {
                let original_key = &token[..idx];
                tokens.push(format!("{original_key}{sep}[REDACTED]"));
                continue;
            }
        }

        let normalized = lower
            .trim_start_matches('-')
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .to_string();
        if is_sensitive_key(&normalized) {
            tokens.push(token.to_string());
            mask_next = true;
            continue;
        }

        tokens.push(token.to_string());
    }

    truncate_chars(&tokens.join(" "), max_chars)
}

pub(crate) fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut truncated = input.chars().take(max_chars).collect::<String>();
    truncated.push_str("...[truncated]");
    truncated
}

fn is_sensitive_key(key: &str) -> bool {
    SENSITIVE_KEYS
        .iter()
        .any(|candidate| key.contains(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_key_value_tokens() {
        let redacted = redact_sensitive_text("cmd --token=abc password secret", 200);
        assert!(redacted.contains("--token=[REDACTED]"));
        assert!(redacted.contains("password [REDACTED]"));
        assert!(!redacted.contains("abc"));
        assert!(!redacted.contains("secret"));
    }

    #[test]
    fn truncates_long_text() {
        let truncated = redact_sensitive_text("abcdef", 3);
        assert_eq!(truncated, "abc...[truncated]");
    }
}

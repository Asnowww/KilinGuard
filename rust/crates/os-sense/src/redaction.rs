const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "credential",
    "signature",
    "private_key",
    "client_secret",
    "auth",
    "authorization",
];

pub(crate) fn redact_sensitive_text(input: &str, max_chars: usize) -> String {
    let mut mask_next = 0usize;
    let mut tokens = Vec::new();

    for token in input.split_whitespace() {
        if mask_next > 0 {
            tokens.push("[REDACTED]".to_string());
            mask_next -= 1;
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
                let value = token[idx + 1..].trim_matches(|ch| matches!(ch, '\'' | '"'));
                let credential_scheme = value
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase();
                if key.contains("auth") && matches!(credential_scheme.as_str(), "bearer" | "basic")
                {
                    mask_next = 1;
                } else if value.is_empty() {
                    mask_next = if key.contains("auth") { 2 } else { 1 };
                } else if token[idx + 1..]
                    .chars()
                    .filter(|ch| matches!(ch, '\'' | '"'))
                    .count()
                    % 2
                    == 1
                {
                    mask_next = 1;
                }
                continue;
            }
        }

        let normalized = lower
            .trim_start_matches('-')
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .to_string();
        if is_sensitive_key(&normalized) {
            tokens.push(token.to_string());
            mask_next = if normalized.contains("auth") { 2 } else { 1 };
            continue;
        }
        if matches!(normalized.as_str(), "bearer" | "basic") {
            tokens.push(normalized);
            mask_next = 1;
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
    fn redacts_authorization_json_url_and_cloud_credentials() {
        let redacted = redact_sensitive_text(
            r#"Authorization: Bearer topsecret {"password":"quoted value"} https://host/path?X-Amz-Signature=signed&api_key=second credential=cloud"#,
            500,
        );
        assert!(!redacted.contains("topsecret"));
        assert!(!redacted.contains("quoted"));
        assert!(!redacted.contains("value"));
        assert!(!redacted.contains("signed"));
        assert!(!redacted.contains("second"));
        assert!(!redacted.contains("cloud"));
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_credentials_after_adjacent_authorization_scheme() {
        let redacted = redact_sensitive_text(
            "Authorization:Bearer topsecret --authorization=Basic dXNlcjpwYXNz safe",
            500,
        );
        assert!(!redacted.contains("topsecret"));
        assert!(!redacted.contains("dXNlcjpwYXNz"));
        assert!(redacted.contains("Authorization:[REDACTED] [REDACTED]"));
        assert!(redacted.contains("--authorization=[REDACTED] [REDACTED]"));
        assert!(redacted.ends_with("safe"));
    }

    #[test]
    fn truncates_long_text() {
        let truncated = redact_sensitive_text("abcdef", 3);
        assert_eq!(truncated, "abc...[truncated]");
    }
}

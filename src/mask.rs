//! Masking strategies for PII values

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Masking strategy to use when replacing PII
#[derive(Debug, Clone, PartialEq)]
pub enum MaskStrategy {
    /// Replace with a masked string like "[EMAIL]" or "[PHONE]"
    Replace,
    /// Replace with a deterministic hash based on original value
    Hash,
    /// Replace with a fully redacted string of asterisks
    Redact,
}

impl MaskStrategy {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "replace" => Ok(Self::Replace),
            "hash" => Ok(Self::Hash),
            "redact" => Ok(Self::Redact),
            _ => Err(format!("Unknown masking strategy: {}", s)),
        }
    }

    /// Mask a value according to the strategy and PII type category
    pub fn mask(&self, value: &str, _category: &str, pattern_name: &str) -> String {
        match self {
            Self::Replace => format!("[{}]", pattern_name.to_uppercase()),
            Self::Hash => {
                let mut hasher = Sha256::new();
                hasher.update(value.as_bytes());
                let result = hasher.finalize();
                let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
                format!("[HASH:{}...{}]", &hex[..8], &hex[hex.len() - 8..])
            }
            Self::Redact => {
                let len = value.len().max(8);
                "•".repeat(len)
            }
        }
    }

    /// Generate a deterministic masked value based on input and an optional salt
    pub fn mask_with_salt(&self, value: &str, salt: &str) -> String {
        match self {
            Self::Replace => {
                let mut hasher = Sha256::new();
                hasher.update(value.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let uuid = Uuid::from_slice(&result[..16]).unwrap();
                format!("[MASK:{}]", uuid)
            }
            Self::Hash => self.mask(value, "", "hash"),
            Self::Redact => {
                let mut hasher = Sha256::new();
                hasher.update(value.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let uuid = Uuid::from_slice(&result[..16]).unwrap();
                format!("••••{}••••", &uuid.to_string()[..8])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_strategy() {
        let strategy = MaskStrategy::Replace;
        let result = strategy.mask("test@example.com", "contact", "email");
        assert_eq!(result, "[EMAIL]");
    }

    #[test]
    fn test_hash_strategy() {
        let strategy = MaskStrategy::Hash;
        let result = strategy.mask("test@example.com", "contact", "email");
        assert!(result.starts_with("[HASH:"));
        assert!(result.contains("..."));
        assert!(result.ends_with("]"));
    }

    #[test]
    fn test_redact_strategy() {
        let strategy = MaskStrategy::Redact;
        let result = strategy.mask("test@example.com", "contact", "email");
        assert!(result.chars().all(|c| c == '•'));
        // • is multi-byte in UTF-8, so byte length differs from char count
        assert!(result.chars().count() >= 8);
    }

    #[test]
    fn test_mask_with_salt_deterministic() {
        let strategy = MaskStrategy::Replace;
        let val = "test@example.com";
        let salt = "my-salt";

        let r1 = strategy.mask_with_salt(val, salt);
        let r2 = strategy.mask_with_salt(val, salt);
        assert_eq!(r1, r2);

        let r3 = strategy.mask_with_salt(val, "different-salt");
        assert_ne!(r1, r3);
    }

    #[test]
    fn test_from_str_valid() {
        assert!(MaskStrategy::from_str("replace").is_ok());
        assert!(MaskStrategy::from_str("hash").is_ok());
        assert!(MaskStrategy::from_str("redact").is_ok());
        assert!(MaskStrategy::from_str("unknown").is_err());
    }

    #[test]
    fn test_from_str_case_insensitive() {
        assert_eq!(
            MaskStrategy::from_str("REPLACE").unwrap(),
            MaskStrategy::Replace
        );
        assert_eq!(MaskStrategy::from_str("HASH").unwrap(), MaskStrategy::Hash);
        assert_eq!(
            MaskStrategy::from_str("REDACT").unwrap(),
            MaskStrategy::Redact
        );
    }
}

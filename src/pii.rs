//! PII detection engine with configurable detection levels

use regex::Regex;
use std::collections::HashMap;

/// Detection mode determines sensitivity
#[derive(Debug, Clone, PartialEq)]
pub enum DetectionLevel {
    /// Strict: only high-confidence patterns
    Strict,
    /// Moderate: balanced detection (default)
    Moderate,
    /// Relaxed: catches more potential PII with higher false-positive rate
    Relaxed,
}

impl DetectionLevel {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "moderate" => Ok(Self::Moderate),
            "relaxed" => Ok(Self::Relaxed),
            _ => Err(format!("Unknown detection level: {}", s)),
        }
    }

    pub fn patterns(&self) -> Vec<PIIPattern> {
        let mut patterns = Vec::new();
        patterns.extend(self.common_patterns());

        match self {
            Self::Moderate | Self::Relaxed => {
                patterns.extend(self.email_phone_patterns());
            }
            Self::Strict => {}
        }

        if let Self::Relaxed = self {
            patterns.extend(self.loose_patterns());
        }

        patterns
    }

    fn common_patterns(&self) -> Vec<PIIPattern> {
        vec![
            PIIPattern {
                name: "email",
                description: "Email address",
                regex: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
                replacement: "[EMAIL]",
                category: "contact",
            },
            PIIPattern {
                name: "ipv4",
                description: "IPv4 address",
                regex: Regex::new(
                    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
                )
                .unwrap(),
                replacement: "[IP_ADDRESS]",
                category: "network",
            },
            PIIPattern {
                name: "credit_card",
                description: "Credit card number (13-19 digits)",
                regex: Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap(),
                replacement: "[CREDIT_CARD]",
                category: "financial",
            },
            PIIPattern {
                name: "ssn",
                description: "US Social Security Number",
                regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                replacement: "[SSN]",
                category: "government_id",
            },
            PIIPattern {
                name: "phone_us",
                description: "US phone number",
                regex: Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap(),
                replacement: "[PHONE]",
                category: "contact",
            },
        ]
    }

    fn email_phone_patterns(&self) -> Vec<PIIPattern> {
        vec![
            PIIPattern {
                name: "phone_intl",
                description: "International phone number",
                regex: Regex::new(r"\+\d{1,3}[-.\s]?\d{4,14}").unwrap(),
                replacement: "[PHONE]",
                category: "contact",
            },
            PIIPattern {
                name: "ip_v6",
                description: "IPv6 address",
                regex: Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b").unwrap(),
                replacement: "[IP_ADDRESS]",
                category: "network",
            },
        ]
    }

    fn loose_patterns(&self) -> Vec<PIIPattern> {
        vec![
            PIIPattern {
                name: "url",
                description: "URL with potential credentials",
                regex: Regex::new(r#"https?://[^\s<>"')\]{},]+"#).unwrap(),
                replacement: "[URL]",
                category: "web",
            },
            PIIPattern {
                name: "uuid",
                description: "UUID/GUID",
                regex: Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").unwrap(),
                replacement: "[UUID]",
                category: "identifier",
            },
        ]
    }
}

/// A single PII pattern definition
#[derive(Debug, Clone)]
pub struct PIIPattern {
    pub name: &'static str,
    pub description: &'static str,
    pub regex: Regex,
    #[expect(dead_code)]
    pub replacement: &'static str,
    pub category: &'static str,
}

/// A detected PII instance
#[derive(Debug, Clone)]
pub struct PIIHit {
    pub pattern_name: String,
    pub description: String,
    pub category: String,
    pub value: String,
    pub line_number: usize,
    pub column: usize,
}

/// Scan a line of text and return all PII hits
pub fn scan_line(text: &str, level: &DetectionLevel, line_number: usize) -> Vec<PIIHit> {
    let patterns = level.patterns();
    let mut hits = Vec::new();

    for pattern in &patterns {
        for cap in pattern.regex.find_iter(text) {
            hits.push(PIIHit {
                pattern_name: pattern.name.to_string(),
                description: pattern.description.to_string(),
                category: pattern.category.to_string(),
                value: cap.as_str().to_string(),
                line_number,
                column: cap.start(),
            });
        }
    }

    hits.sort_by_key(|h| h.column);
    hits
}

/// Count how many unique PII types are in the text
#[expect(dead_code)]
pub fn count_types(text: &str, level: &DetectionLevel) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    let hits = scan_line(text, level, 0);

    for hit in hits {
        *counts.entry(hit.category).or_insert(0) += 1;
    }

    counts
}

/// Check if text contains any PII
#[expect(dead_code)]
pub fn has_pii(text: &str, level: &DetectionLevel) -> bool {
    !scan_line(text, level, 0).is_empty()
}

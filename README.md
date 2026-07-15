# datamask

Detect and anonymize PII (Personally Identifiable Information) in CSV and JSON files. A standalone CLI tool for data privacy compliance, safe data sharing, and test data generation.

## Features

- **Multi-format support**: Process CSV and JSON files, with cross-format conversion (CSV→JSON, JSON→CSV)
- **Configurable detection levels**: `strict` (high-confidence only), `moderate` (balanced, default), `relaxed` (catch-all)
- **Three masking strategies**: `hash` (deterministic SHA-256 based), `replace` (category-based labels), `redact` (asterisk masking)
- **Scan mode**: Detect PII without modifying data — perfect for auditing
- **Key-aware masking**: Recognizes field names like `email`, `phone`, `ssn`, `password` for automatic masking
- **Deterministic output**: Same input + salt always produces the same masked output
- **JSON output**: Structured scan results for programmatic integration

## PII Patterns Detected

| Level | Patterns |
|-------|----------|
| Strict | Email addresses, IPv4 addresses, credit card numbers, SSNs, US phone numbers |
| Moderate | All strict + international phone numbers, IPv6 addresses |
| Relaxed | All moderate + URLs, UUIDs |

## Installation

### From Source (Rust)

```bash
cargo install --path .
```

### Using Cargo

```bash
cargo add datamask
```

## Quick Start

### Scan a CSV file for PII

```bash
datamask --input data.csv --scan
```

### Scan and output results as JSON

```bash
datamask --input data.csv --scan --scan-json
```

### Anonymize a CSV file

```bash
datamask --input data.csv --output anonymized.csv
```

### Change detection sensitivity

```bash
datamask --input data.csv --output anonymized.csv --detection strict
datamask --input data.csv --output anonymized.csv --detection relaxed
```

### Change masking strategy

```bash
datamask --input data.csv --output anonymized.csv --strategy replace
datamask --input data.csv --output anonymized.csv --strategy redact
datamask --input data.csv --output anonymized.csv --strategy hash
```

### Convert CSV to JSON with masking

```bash
datamask --input data.csv --out-format json --output masked.json
```

### Process JSON input

```bash
datamask --input data.json --format json --output masked.json
```

### Pipe data from stdin

```bash
cat data.csv | datamask --output masked.csv
```

### Custom CSV delimiter

```bash
datamask --input data.tsv --delimiter $'\t' --output masked.csv
```

## Examples

### Sample CSV Input (`data.csv`)

```csv
name,email,phone,city
John Doe,john@example.com,555-123-4567,New York
Jane Smith,jane@test.org,555-987-6543,Los Angeles
```

### Default Output (hash masking)

```csv
name,email,phone,city
John Doe,[HASH:a1b2c3d4...e5f6a7b8],[HASH:9c8d7e6f...1a2b3c4d],New York
Jane Smith,[HASH:f1e2d3c4...b5a69788],[HASH:4d5e6f7a...8c9d0e1f],Los Angeles
```

### Replace Strategy Output

```csv
name,email,phone,city
John Doe,[EMAIL],[PHONE],New York
Jane Smith,[EMAIL],[PHONE],Los Angeles
```

### Scan Mode Output

```json
[
  {
    "pattern": "email",
    "description": "Email address",
    "category": "contact",
    "value": "john@example.com",
    "line": 2,
    "column": 11
  },
  {
    "pattern": "phone_us",
    "description": "US phone number",
    "category": "contact",
    "value": "555-123-4567",
    "line": 2,
    "column": 31
  }
]
```

## API Usage (Library)

```rust
use datamask::pii::{DetectionLevel, scan_line};
use datamask::mask::MaskStrategy;

fn main() {
    let level = DetectionLevel::Moderate;
    let strategy = MaskStrategy::Hash;

    let text = "Contact John at john@example.com or 555-123-4567";
    let hits = scan_line(&text, &level, 1);

    for hit in hits {
        println!("Found {}: {} at line {}", hit.pattern_name, hit.value, hit.line_number);
    }
}
```

## Architecture

```
datamask/
├── src/
│   ├── main.rs          # Entry point
│   ├── cli.rs           # CLI argument parsing (clap)
│   ├── pii.rs           # PII pattern definitions and detection engine
│   ├── mask.rs          # Masking strategies (hash, replace, redact)
│   └── engine.rs        # Core processing logic (CSV/JSON handling)
├── tests/               # Integration tests
├── Cargo.toml           # Rust dependencies
├── README.md            # This file
├── LICENSE              # MIT License
├── AGENTS.md            # AI agent instructions
└── .github/workflows/   # CI configuration
```

## Development

```bash
# Run tests
cargo test

# Build release binary
cargo build --release

# Run clippy
cargo clippy -- -D warnings

# Format code
cargo fmt
```

## Security Considerations

- PII detection is pattern-based and may have false positives/negatives
- For production use with sensitive data, combine with professional data classification tools
- The hash-based masking is deterministic — use different salts for different datasets
- The tool does not encrypt data at rest

## License

MIT — see [LICENSE](LICENSE) for details.

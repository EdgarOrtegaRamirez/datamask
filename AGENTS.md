# AGENTS.md

## datamask

A Rust CLI tool for detecting and anonymizing PII (Personally Identifiable Information) in CSV and JSON files.

### Project Structure

```
datamask/
├── src/
│   ├── main.rs          # Entry point - parses CLI args and runs engine
│   ├── cli.rs           # CLI argument definitions using clap derive
│   ├── pii.rs           # PII detection engine with configurable sensitivity levels
│   ├── mask.rs          # Masking strategies: hash (SHA-256), replace, redact
│   └── engine.rs        # Core processing: CSV/JSON parsing, masking orchestration
├── tests/               # Integration tests
├── Cargo.toml           # Dependencies
└── README.md            # Usage documentation
```

### Key Modules

**pii.rs** - Contains `DetectionLevel` enum (Strict/Moderate/Relaxed) and `PIIPattern` definitions. Each pattern has a regex, category, and replacement string. Detects: email, IPv4/IPv6, credit cards, SSNs, phone numbers, URLs, UUIDs.

**mask.rs** - `MaskStrategy` enum with three variants:
- `Replace`: Returns category labels like `[EMAIL]`, `[PHONE]`
- `Hash`: Deterministic SHA-256 based masking with salt
- `Redact`: Asterisk masking preserving value length

**engine.rs** - Orchestrates the full pipeline:
- `run()` - Main entry point
- `process_csv()` - CSV processing with header support
- `process_json()` - JSON recursive masking
- `mask_field()` - Single value masking logic
- `mask_value()` - Recursive JSON value masking
- Supports stdin/stdout for piping

**cli.rs** - Clap-based CLI with args: input, output, format, out_format, detection, strategy, scan, scan_json, fields, no_header, delimiter

### Dependencies

- `clap` (derive) - CLI argument parsing
- `regex` - Pattern matching for PII detection
- `serde` / `serde_json` - JSON serialization
- `csv` - CSV parsing
- `sha2` - Hash-based masking
- `uuid` - UUID generation for deterministic masking
- `anyhow` / `thiserror` - Error handling
- `color-eyre` - Enhanced error reporting

### Building

```bash
cargo build --release
```

### Testing

```bash
cargo test
```

### Running

```bash
# Scan for PII
datamask --input data.csv --scan

# Mask CSV
datamask --input data.csv --output masked.csv

# Mask JSON
datamask --input data.json --format json

# Pipe from stdin
cat data.csv | datamask

# Full options
datamask --input data.csv --output masked.json --detection relaxed --strategy replace --out-format json
```

### API Usage

```rust
use datamask::pii::{DetectionLevel, scan_line};
use datamask::mask::MaskStrategy;

let level = DetectionLevel::Moderate;
let strategy = MaskStrategy::Hash;
let hits = scan_line("john@example.com", &level, 1);
let masked = strategy.mask_with_salt("john@example.com", "salt");
```

### Security Notes

- No external API calls or network requests
- All PII processing is local
- Hash-based masking is deterministic (same input + salt = same output)
- No secrets or tokens in source code
- All dependencies are well-maintained crates

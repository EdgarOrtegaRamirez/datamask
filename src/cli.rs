use clap::Parser;
use std::path::PathBuf;

/// datamask — Detect and anonymize PII in CSV and JSON files
#[derive(Parser, Debug)]
#[command(name = "datamask", version, about)]
pub struct App {
    /// Input file path (stdin if not provided)
    #[arg(short, long)]
    pub input: Option<PathBuf>,

    /// Output file path (stdout if not provided)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Input format: csv or json
    #[arg(short, long, default_value = "csv")]
    pub format: String,

    /// Output format: csv or json
    #[arg(short = 'O', long, default_value = "csv")]
    pub out_format: String,

    /// Detection mode: strict, moderate, or relaxed
    #[arg(short, long, default_value = "moderate")]
    pub detection: String,

    /// Masking strategy: hash, replace, or redact
    #[arg(short, long, default_value = "hash")]
    pub strategy: String,

    /// Show detected PII without masking
    #[arg(long)]
    pub scan: bool,

    /// Output scan results as JSON
    #[arg(long)]
    pub scan_json: bool,

    /// Field names to include/exclude in scanning (comma-separated)
    #[arg(long)]
    pub fields: Option<String>,

    /// Skip header row
    #[arg(long)]
    pub no_header: bool,

    /// Delimiter for CSV input
    #[arg(long, default_value = ",")]
    pub delimiter: String,
}

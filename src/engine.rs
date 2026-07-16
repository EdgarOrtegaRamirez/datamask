//! Core engine that orchestrates detection and masking

use crate::cli::App;
use crate::mask::MaskStrategy;
use crate::pii::{scan_line, DetectionLevel, PIIHit};
use anyhow::{Context, Result};
use std::fs;
use std::io::{self, BufRead, BufWriter, Write};

/// Run the main datamask workflow
pub fn run(app: &App) -> Result<()> {
    let level = DetectionLevel::from_str(&app.detection).map_err(|e| anyhow::anyhow!("{}", e))?;
    let strategy = MaskStrategy::from_str(&app.strategy).map_err(|e| anyhow::anyhow!("{}", e))?;

    let input_text = read_input(&app.input)?;

    if app.scan || app.scan_json {
        return run_scan(&input_text, &level, app.scan_json);
    }

    match app.format.as_str() {
        "csv" => process_csv(&input_text, app, &level, &strategy),
        "json" => process_json(&input_text, app, &level, &strategy),
        other => Err(anyhow::anyhow!(
            "Unsupported format: {}. Use 'csv' or 'json'",
            other
        )),
    }
}

/// Run in scan-only mode — detect but don't mask
fn run_scan(input: &str, level: &DetectionLevel, as_json: bool) -> Result<()> {
    let mut total_hits: Vec<PIIHit> = Vec::new();

    for (i, line) in input.lines().enumerate() {
        let hits = scan_line(line, level, i + 1);
        total_hits.extend(hits);
    }

    if as_json {
        let hits_json: Vec<serde_json::Value> = total_hits
            .iter()
            .map(|h| {
                serde_json::json!({
                    "pattern": h.pattern_name,
                    "description": h.description,
                    "category": h.category,
                    "value": h.value,
                    "line": h.line_number,
                    "column": h.column,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&hits_json)?);
    } else if total_hits.is_empty() {
        println!("No PII detected.");
    } else {
        println!("PII Detection Report");
        println!("====================");
        println!("Total hits: {}\n", total_hits.len());

        let mut by_category: std::collections::HashMap<String, Vec<&PIIHit>> =
            std::collections::HashMap::new();
        for hit in &total_hits {
            by_category
                .entry(hit.category.clone())
                .or_default()
                .push(hit);
        }

        for (category, hits) in &by_category {
            println!("{} ({})", category.to_uppercase(), hits.len());
            for hit in hits.iter().take(5) {
                println!(
                    "  Line {}: {} — {}",
                    hit.line_number, hit.pattern_name, hit.value
                );
            }
            if hits.len() > 5 {
                println!("  ... and {} more", hits.len() - 5);
            }
        }
    }

    Ok(())
}

/// Process CSV input
fn process_csv(
    input: &str,
    app: &App,
    level: &DetectionLevel,
    strategy: &MaskStrategy,
) -> Result<()> {
    let mut writer = BufWriter::new(get_output_writer(&app.output)?);

    if app.out_format == "json" {
        process_csv_to_json(input, app, level, strategy, &mut writer)
    } else {
        process_csv_csv(input, app, level, strategy, &mut writer)
    }
}

fn process_csv_to_json(
    input: &str,
    app: &App,
    level: &DetectionLevel,
    strategy: &MaskStrategy,
    writer: &mut BufWriter<Box<dyn Write>>,
) -> Result<()> {
    let mut records = Vec::new();
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(app.delimiter.as_bytes()[0])
        .has_headers(!app.no_header)
        .from_reader(input.as_bytes());

    let headers = reader.headers()?.clone();

    for row in reader.records() {
        let row = row?;
        let mut record = serde_json::Map::new();

        for (i, field) in row.iter().enumerate() {
            let key = if i < headers.len() {
                headers[i].to_string()
            } else {
                format!("field_{}", i)
            };
            let masked = mask_field(field, &key, level, strategy);
            record.insert(key, serde_json::Value::String(masked));
        }
        records.push(serde_json::Value::Object(record));
    }

    writeln!(writer, "{}", serde_json::to_string_pretty(&records)?)?;
    Ok(())
}

fn process_csv_csv(
    input: &str,
    app: &App,
    level: &DetectionLevel,
    strategy: &MaskStrategy,
    writer: &mut BufWriter<Box<dyn Write>>,
) -> Result<()> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(app.delimiter.as_bytes()[0])
        .has_headers(!app.no_header)
        .from_reader(input.as_bytes());

    let headers = reader.headers()?.clone();
    let mut header_written = false;

    for result in reader.records() {
        let row = result?;

        let fields: Vec<String> = (0..row.len())
            .map(|i| {
                let key = if i < headers.len() {
                    headers[i].to_string()
                } else {
                    format!("field_{}", i)
                };
                mask_field(row.get(i).unwrap_or(""), &key, level, strategy)
            })
            .collect();

        if !header_written && !app.no_header {
            let header_vals: Vec<String> = headers.iter().map(|s| s.to_string()).collect();
            writeln!(writer, "{}", header_vals.join(","))?;
            header_written = true;
        }

        writeln!(writer, "{}", fields.join(","))?;
    }

    writer.flush()?;
    Ok(())
}

/// Process JSON input
fn process_json(
    input: &str,
    app: &App,
    level: &DetectionLevel,
    strategy: &MaskStrategy,
) -> Result<()> {
    let parsed: serde_json::Value = serde_json::from_str(input)?;
    let masked = mask_value(&parsed, "", level, strategy);

    if app.out_format == "csv" {
        let records = flatten_json(&masked);
        let mut writer = BufWriter::new(get_output_writer(&app.output)?);
        for (i, record) in records.iter().enumerate() {
            if i == 0 {
                let headers: Vec<String> = record.keys().cloned().collect();
                writeln!(writer, "{}", headers.join(","))?;
            }
            let values: Vec<String> = record.values().map(|v| v.to_string()).collect();
            writeln!(writer, "{}", values.join(","))?;
        }
    } else {
        let output = serde_json::to_string_pretty(&masked)?;
        let mut writer = get_output_writer(&app.output)?;
        writer.write_all(output.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }

    Ok(())
}

/// Mask a single value based on its context key and PII detection
fn mask_field(value: &str, key: &str, level: &DetectionLevel, strategy: &MaskStrategy) -> String {
    if value.is_empty() {
        return value.to_string();
    }

    let key_lower = key.to_lowercase();

    let sensitive_keys = [
        "email",
        "phone",
        "ssn",
        "password",
        "secret",
        "token",
        "api_key",
        "credit_card",
        "address",
        "name",
        "date_of_birth",
    ];

    if sensitive_keys.iter().any(|k| key_lower.contains(k)) {
        return strategy.mask(value, "sensitive", key);
    }

    let hits = scan_line(value, level, 0);
    if hits.is_empty() {
        return value.to_string();
    }

    let mut result = value.to_string();
    for hit in hits.iter().rev() {
        if hit.line_number == 0 {
            let masked = strategy.mask_with_salt(&hit.value, key);
            if let Some(pos) = result.find(&hit.value) {
                result.replace_range(pos..pos + hit.value.len(), &masked);
            }
        }
    }

    result
}

/// Recursively mask a JSON value
fn mask_value(
    value: &serde_json::Value,
    key: &str,
    level: &DetectionLevel,
    strategy: &MaskStrategy,
) -> serde_json::Value {
    match value {
        serde_json::Value::Null => value.clone(),
        serde_json::Value::Bool(_) => value.clone(),
        serde_json::Value::Number(_) => value.clone(),
        serde_json::Value::String(s) => {
            if s.is_empty() {
                return value.clone();
            }

            let key_lower = key.to_lowercase();
            let sensitive_keys = [
                "email",
                "phone",
                "ssn",
                "password",
                "secret",
                "token",
                "api_key",
                "credit_card",
                "address",
                "name",
                "date_of_birth",
                "birth_date",
                "dob",
                "mobilenumber",
                "mobileno",
            ];

            if sensitive_keys.iter().any(|k| key_lower.contains(k)) {
                return serde_json::Value::String(strategy.mask_with_salt(s, key));
            }

            let hits = scan_line(s, level, 0);
            if hits.is_empty() {
                return value.clone();
            }

            let mut result = s.to_string();
            for hit in hits.iter().rev() {
                let masked = strategy.mask_with_salt(&hit.value, key);
                if let Some(pos) = result.find(&hit.value) {
                    result.replace_range(pos..pos + hit.value.len(), &masked);
                }
            }

            serde_json::Value::String(result)
        }
        serde_json::Value::Array(arr) => {
            let masked: Vec<serde_json::Value> = arr
                .iter()
                .map(|v| mask_value(v, key, level, strategy))
                .collect();
            serde_json::Value::Array(masked)
        }
        serde_json::Value::Object(obj) => {
            let mut masked = serde_json::Map::new();
            for (k, v) in obj {
                masked.insert(k.clone(), mask_value(v, k, level, strategy));
            }
            serde_json::Value::Object(masked)
        }
    }
}

/// Flatten a JSON value into a list of flat maps
fn flatten_json(value: &serde_json::Value) -> Vec<serde_json::Map<String, serde_json::Value>> {
    match value {
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                return vec![];
            }
            if let Some(first) = arr.first() {
                match first {
                    serde_json::Value::Object(_) => arr
                        .iter()
                        .filter_map(|v| {
                            if let serde_json::Value::Object(obj) = v {
                                Some(obj.clone())
                            } else {
                                None
                            }
                        })
                        .collect(),
                    _ => {
                        let mut maps: Vec<serde_json::Map<String, serde_json::Value>> = Vec::new();
                        for v in arr.iter() {
                            let mut map = serde_json::Map::new();
                            map.insert("value".to_string(), v.clone());
                            maps.push(map);
                        }
                        maps
                    }
                }
            } else {
                vec![]
            }
        }
        serde_json::Value::Object(obj) => vec![obj.clone()],
        _ => {
            let mut map = serde_json::Map::new();
            map.insert("value".to_string(), value.clone());
            vec![map]
        }
    }
}

/// Get a writer for output — stdout or file
fn get_output_writer(path: &Option<std::path::PathBuf>) -> Result<Box<dyn Write>> {
    match path {
        Some(p) => {
            let file = fs::File::create(p)
                .with_context(|| format!("Failed to create output file: {:?}", p))?;
            Ok(Box::new(BufWriter::new(file)))
        }
        None => Ok(Box::new(io::stdout())),
    }
}

/// Read input from file or stdin
fn read_input(path: &Option<std::path::PathBuf>) -> Result<String> {
    match path {
        Some(p) => {
            fs::read_to_string(p).with_context(|| format!("Failed to read input file: {:?}", p))
        }
        None => {
            let stdin = io::stdin();
            let mut lines = Vec::new();
            let reader = stdin.lock();
            for line in reader.lines() {
                lines.push(line?);
            }
            Ok(lines.join("\n"))
        }
    }
}

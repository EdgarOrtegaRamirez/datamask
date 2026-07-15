//! Main entry point for datamask

mod cli;
mod engine;
mod mask;
mod pii;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let app = cli::App::parse();
    engine::run(&app)?;
    Ok(())
}

//! Product-owned machine-output serialization for the standalone CLI.
//!
//! Query handlers return typed results and errors. This module is the only CLI
//! owner that turns those values into machine JSON, so individual commands
//! cannot drift between pretty/compact success output or omit typed failures.

use serde::Serialize;

use crate::error::LiganError;

pub fn print_machine_json(value: &impl Serialize) -> Result<(), LiganError> {
    let serialized = serde_json::to_string(value)
        .map_err(|error| LiganError::Config(format!("serialize machine JSON: {error}")))?;
    println!("{serialized}");
    Ok(())
}

pub fn print_domain_error(
    error: &h00ligan_engine::code_intel_domain::DomainError,
) -> Result<(), LiganError> {
    print_machine_json(&error.envelope())
}

//! Native CLI adapters for the shipped `type`, `read`, and `calls` queries.
//!
//! Each adapter delegates one request to the immutable snapshot owner and only
//! renders its typed result. Query, authority, pagination, and envelope policy
//! remain engine/interface concerns shared with MCP.

use clap::Args;

use h00ligan_engine::code_intel_domain::{
    AuthorityStatus, CallerFilter, CallsRequest, DEFAULT_CALLS_PAGE_SIZE, DEFAULT_TYPE_PAGE_SIZE,
    TypeRequest,
};
use h00ligan_engine::code_intel_read::{DEFAULT_READ_PAGE_SIZE, ExactReadResult, ReadRequest};
use h00ligan_engine::code_intel_type::{ExactTypeResult, TypeMemberRole};
use h00ligan_engine::graph_query::short_name;
use h00ligan_engine::project_binding::ProjectBinding;

use crate::error::LiganError;

/// Output format for all h00ligan commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!(
                "unknown format '{other}', expected 'text' or 'json'"
            )),
        }
    }
}

/// Show complete type structure (fields, methods, impls, trait implementations).
#[derive(Args, Debug, Clone)]
pub struct TypeArgs {
    /// Type name, or an exact symbol_id returned by find.
    pub symbol: String,

    /// Optional repo-relative file path to disambiguate a homonym (same-file >
    /// same-crate). Use the path shown in parentheses for each ambiguous candidate.
    #[arg(long)]
    pub file: Option<String>,

    /// Output format.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Maximum structural members in this page (1–100).
    #[arg(long, default_value_t = DEFAULT_TYPE_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a prior page from the exact generation and Type query.
    #[arg(long)]
    pub cursor: Option<String>,
}

/// `h00ligan type <symbol>` — show complete type structure.
pub async fn run_type(args: TypeArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let request = TypeRequest {
        symbol: args.symbol,
        file: args.file,
        limit: args.limit,
        cursor: args.cursor,
    };
    let result = snapshot.query_type(binding, &request).await?;

    if format == OutputFormat::Json {
        crate::output::print_machine_json(&result)?;
        return Ok(());
    }

    render_type(&result);
    Ok(())
}

fn render_type(result: &ExactTypeResult) {
    println!(
        "TYPE: {} ({})",
        result.resolved_type.name, result.resolved_type.kind
    );
    println!("FILE: {}", result.resolved_type.document_path);
    println!(
        "AUTHORITY: {:?} {} ({}: {:?} structural coverage)",
        result.authority.status,
        result.capability,
        result.resolved_type.language_id,
        result.authority.structural_graph.status
    );
    println!(
        "PAGE: offset {}, returned {}, total {}",
        result.page.offset, result.page.returned, result.page.total_items
    );

    let mut prior_role = None;
    for item in &result.items {
        if prior_role != Some(item.role) {
            println!("\n{}:", type_role_heading(item.role));
            prior_role = Some(item.role);
        }
        let symbol = &item.symbol;
        let display = if symbol.signature.is_empty() {
            short_name(&symbol.name).to_string()
        } else {
            symbol.signature.clone()
        };
        let line = symbol
            .start_line
            .map(|line| format!(":{}", line + 1))
            .unwrap_or_default();
        println!("  {display} ({}{line})", symbol.document_path);
    }

    if result.items.is_empty() {
        println!("\nNo structural members in this type.");
    }
    if let Some(cursor) = &result.page.next_cursor {
        println!("\nNEXT CURSOR: {cursor}");
    }
    for warning in &result.warnings {
        eprintln!("WARNING: {warning}");
    }
}

const fn type_role_heading(role: TypeMemberRole) -> &'static str {
    match role {
        TypeMemberRole::Field => "FIELDS",
        TypeMemberRole::FieldTypeReference => "FIELD TYPE REFERENCES",
        TypeMemberRole::Variant => "VARIANTS",
        TypeMemberRole::PublicMethod => "PUBLIC METHODS",
        TypeMemberRole::PrivateMethod => "PRIVATE METHODS",
        TypeMemberRole::RequiredMethod => "REQUIRED METHODS",
        TypeMemberRole::ProvidedMethod => "PROVIDED METHODS",
        TypeMemberRole::ImplementationBlock => "IMPLEMENTATION BLOCKS",
        TypeMemberRole::ImplementedTrait => "IMPLEMENTED TRAITS",
        TypeMemberRole::Implementor => "IMPLEMENTORS",
    }
}

/// Arguments for `h00ligan read`.
#[derive(Args, Debug, Clone)]
pub struct ReadSymbolArgs {
    /// Symbol name, or an exact symbol_id returned by find.
    pub name: String,

    /// Optional exact repo-relative file path. No cross-file fallback is used.
    #[arg(long)]
    pub file: Option<String>,

    /// Maximum Unicode source characters in this page (1–20000).
    #[arg(long, default_value_t = DEFAULT_READ_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a prior page from the exact generation and Read query.
    #[arg(long)]
    pub cursor: Option<String>,

    /// Output format.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// `h00ligan read <name>` — read a function or type body by name.
pub async fn run_read_symbol(
    args: ReadSymbolArgs,
    binding: &ProjectBinding,
) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let request = ReadRequest {
        symbol: args.name,
        file: args.file,
        limit: args.limit,
        cursor: args.cursor,
    };
    h00ligan_engine::code_intel_read::validate_read_request(&request)?;
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let result = snapshot.query_read(binding, &request).await?;

    if format == OutputFormat::Json {
        crate::output::print_machine_json(&result)?;
        return Ok(());
    }

    render_read(&result);
    Ok(())
}

fn render_read(result: &ExactReadResult) {
    use std::fmt::Write as _;

    let symbol = &result.resolved_symbol;
    let start_line = symbol.definition_span.start_line + 1;
    let end_line = symbol.definition_span.end_line + 1;
    let location = if start_line == end_line {
        format!("{}:{start_line}", symbol.document_path)
    } else {
        format!("{}:{start_line}–{end_line}", symbol.document_path)
    };
    let mut out = String::new();
    let _ = writeln!(out, "READ {}", symbol.name);
    let _ = writeln!(out, "  {} · {location}", symbol.kind);
    let _ = writeln!(
        out,
        "  Authority: {}",
        match result.authority.status {
            AuthorityStatus::Complete => "complete",
            AuthorityStatus::Qualified => "qualified",
        }
    );
    if result.page.offset > 0 || result.page.has_more {
        let _ = writeln!(
            out,
            "  Source page: characters {}..{} of {}",
            result.page.offset,
            result.page.offset + result.page.returned,
            result.page.total_items,
        );
    }
    let _ = writeln!(out);
    for (index, line) in result.source.lines().enumerate() {
        let _ = writeln!(
            out,
            "{:>5} | {}",
            result.source_span.start_line + index + 1,
            line
        );
    }
    if let Some(cursor) = &result.page.next_cursor {
        let _ = writeln!(out, "\nNext cursor: {cursor}");
    }
    for warning in &result.warnings {
        let _ = writeln!(out, "Note: {warning}");
    }
    print!("{out}");
}

/// Find semantic callers of a symbol from the published provider evidence.
#[derive(Args, Debug, Clone)]
pub struct CallsArgs {
    /// Symbol name, or an exact symbol_id returned by find.
    pub symbol: String,

    /// Optional repo-relative file path to disambiguate a homonym (same-file >
    /// same-crate). Use the path shown in parentheses for each ambiguous candidate.
    #[arg(long)]
    pub file: Option<String>,

    /// Output format.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Caller population: live, all, dead, or test_only.
    #[arg(long, default_value = "live")]
    pub filter: CallerFilter,

    /// Maximum call sites in this page (1–100).
    #[arg(long, default_value_t = DEFAULT_CALLS_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a prior page from the exact generation and query that issued it.
    #[arg(long)]
    pub cursor: Option<String>,
}

/// `h00ligan calls <symbol>` — find call sites with source context.
pub async fn run_call_sites(args: CallsArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let request = CallsRequest {
        symbol: args.symbol,
        file: args.file,
        filter: args.filter,
        limit: args.limit,
        cursor: args.cursor,
    };
    let result = snapshot.query_calls(binding, &request).await?;

    if format == OutputFormat::Json {
        crate::output::print_machine_json(&result)?;
        return Ok(());
    }

    println!("CALLS TO {}", result.resolved_symbol.name);
    println!(
        "  {} exact invocation{} across {} source origin{}; authority: {:?} ({})",
        result.page.total_items,
        if result.page.total_items == 1 {
            ""
        } else {
            "s"
        },
        result.total_callers,
        if result.total_callers == 1 { "" } else { "s" },
        result.authority.status,
        result.authority.provider_id,
    );
    println!("  Population: {}", result.authority.population);
    if result.callable_value_bindings > 0 {
        println!(
            "  Qualified dispatch evidence: {} callable-value binding{} (not direct calls)",
            result.callable_value_bindings,
            if result.callable_value_bindings == 1 {
                ""
            } else {
                "s"
            }
        );
    }
    println!(
        "  Page: offset {}, returned {}, limit {}",
        result.page.offset, result.page.returned, result.page.limit
    );
    println!();

    if result.items.is_empty() {
        match result.authority.status {
            AuthorityStatus::Complete => {
                println!(
                    "  No invocation origins in the complete {} population.",
                    result.authority.population
                );
            }
            AuthorityStatus::Qualified => {
                println!(
                    "  No invocation origins in covered source; excluded regions may contain additional calls."
                );
            }
        }
    }
    for (index, item) in result.items.iter().enumerate() {
        let location = format!(
            "{}:{}",
            item.origin.document_path(),
            item.call_span.start_line + 1
        );
        println!(
            "{}. {} ({location})",
            result.page.offset + index + 1,
            item.origin.display_name(),
        );
        for line in item.context.lines() {
            println!("   {line}");
        }
        println!();
    }
    if let Some(cursor) = &result.page.next_cursor {
        println!("NEXT CURSOR: {cursor}");
    }
    for warning in &result.warnings {
        eprintln!("WARNING: {warning}");
    }

    Ok(())
}

fn parse_format(s: &str) -> Result<OutputFormat, LiganError> {
    s.parse::<OutputFormat>().map_err(LiganError::Config)
}

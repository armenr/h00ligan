//! Substrate-free MCP JSON-RPC/stdio adapter.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(feature = "code-intel")]
use crate::tool_api::{admit_code_intel_access, reject_bound_project_switch};
use crate::{ToolDefinition, ToolError};

/// Final ceiling for one assembled MCP tool response.
///
/// Legacy MCP embeds the complete typed JSON value inside a JSON string. In
/// the worst case every character in a domain-bounded value needs one extra
/// escape character, so this transport envelope must accommodate twice the
/// code-intelligence value ceiling plus response metadata.
pub const MAX_TOOL_RESULT_CHARS: usize = 64 * 1_024;
#[cfg(feature = "code-intel")]
const _: () = assert!(
    MAX_TOOL_RESULT_CHARS
        >= 2 * h00ligan_engine::code_intel_domain::MAX_CODE_INTEL_RESULT_CHARS + 2_048
);
const STRUCTURED_CONTENT_NOTICE: &str =
    "Full typed h00ligan result is available in structuredContent.";
const MAX_IN_FLIGHT_REQUESTS: u64 = 32;
pub const CURRENT_PROTOCOL_VERSION: &str = "2026-07-28";
pub const LATEST_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    CURRENT_PROTOCOL_VERSION,
    LATEST_LEGACY_PROTOCOL_VERSION,
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

/// Product-owned identity advertised by the reusable MCP transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpServerIdentity<'a> {
    pub name: &'a str,
    pub version: &'a str,
}

impl<'a> McpServerIdentity<'a> {
    pub const fn new(name: &'a str, version: &'a str) -> Self {
        Self { name, version }
    }
}

#[async_trait::async_trait]
pub trait McpToolDispatcher: Send + Sync {
    fn definitions(&self) -> &[ToolDefinition];

    async fn execute(
        &self,
        name: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ToolError>;

    fn recovery_hint(&self, _name: &str, _error: &ToolError) -> Option<String> {
        None
    }

    async fn shutdown(&self) {}
}

#[cfg(feature = "code-intel")]
pub struct CodeIntelMcp {
    registry: crate::CodeIntelRegistry,
    context: crate::CodeIntelContext,
}

#[cfg(feature = "code-intel")]
impl CodeIntelMcp {
    pub const fn new(registry: crate::CodeIntelRegistry, context: crate::CodeIntelContext) -> Self {
        Self { registry, context }
    }

    pub const fn context(&self) -> &crate::CodeIntelContext {
        &self.context
    }
}

#[cfg(feature = "code-intel")]
#[async_trait::async_trait]
impl McpToolDispatcher for CodeIntelMcp {
    fn definitions(&self) -> &[ToolDefinition] {
        self.registry.definitions()
    }

    async fn execute(
        &self,
        name: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ToolError> {
        reject_bound_project_switch(&input)?;
        let definition = self
            .registry
            .definitions()
            .iter()
            .find(|definition| definition.name == name)
            .ok_or_else(|| ToolError::UnknownTool(name.into()))?;
        validate_schema(&input, &definition.input_schema, "arguments")?;

        let access = self.registry.access(name, &input)?;
        admit_code_intel_access(&self.context, access).await?;
        self.registry.execute(name, input, &self.context).await
    }

    fn recovery_hint(&self, name: &str, error: &ToolError) -> Option<String> {
        self.registry.recovery_hint(name, error)
    }

    async fn shutdown(&self) {
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.context.shutdown_indexing(),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "WATCH shutdown failed before MCP exit"),
            Err(_) => tracing::warn!(
                "index supervisor did not reach a terminal receipt before MCP shutdown"
            ),
        }
    }
}

fn validate_schema(
    value: &serde_json::Value,
    schema: &serde_json::Value,
    path: &str,
) -> Result<(), ToolError> {
    if let Some(expected) = schema.get("type") {
        let matches = match expected {
            serde_json::Value::String(expected) => value_matches_type(value, expected),
            serde_json::Value::Array(expected) => expected
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|expected| value_matches_type(value, expected)),
            _ => false,
        };
        if !matches {
            return Err(ToolError::InvalidInput(format!(
                "{path} must be {}",
                schema_type_label(expected)
            )));
        }
    }

    if let Some(allowed) = schema.get("enum").and_then(serde_json::Value::as_array)
        && !allowed.iter().any(|candidate| candidate == value)
    {
        return Err(ToolError::InvalidInput(format!(
            "{path} must match one of the advertised enum values"
        )));
    }

    if let Some(number) = value.as_f64() {
        if let Some(minimum) = schema.get("minimum").and_then(serde_json::Value::as_f64)
            && number < minimum
        {
            return Err(ToolError::InvalidInput(format!(
                "{path} violates minimum {minimum}"
            )));
        }
        if let Some(maximum) = schema.get("maximum").and_then(serde_json::Value::as_f64)
            && number > maximum
        {
            return Err(ToolError::InvalidInput(format!(
                "{path} exceeds maximum {maximum}"
            )));
        }
    }

    if let Some(text) = value.as_str() {
        let length = text.chars().count() as u64;
        if let Some(minimum) = schema.get("minLength").and_then(serde_json::Value::as_u64)
            && length < minimum
        {
            return Err(ToolError::InvalidInput(format!(
                "{path} violates minLength {minimum}"
            )));
        }
        if let Some(maximum) = schema.get("maxLength").and_then(serde_json::Value::as_u64)
            && length > maximum
        {
            return Err(ToolError::InvalidInput(format!(
                "{path} exceeds maxLength {maximum}"
            )));
        }
    }

    if let Some(values) = value.as_array() {
        let length = values.len() as u64;
        if let Some(minimum) = schema.get("minItems").and_then(serde_json::Value::as_u64)
            && length < minimum
        {
            return Err(ToolError::InvalidInput(format!(
                "{path} violates minItems {minimum}"
            )));
        }
        if let Some(maximum) = schema.get("maxItems").and_then(serde_json::Value::as_u64)
            && length > maximum
        {
            return Err(ToolError::InvalidInput(format!(
                "{path} exceeds maxItems {maximum}"
            )));
        }
        if schema.get("uniqueItems") == Some(&serde_json::Value::Bool(true)) {
            for (index, item) in values.iter().enumerate() {
                if values[..index].iter().any(|previous| previous == item) {
                    return Err(ToolError::InvalidInput(format!(
                        "{path} violates uniqueItems at index {index}"
                    )));
                }
            }
        }
    }

    if let Some(object) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(serde_json::Value::as_array) {
            for name in required.iter().filter_map(serde_json::Value::as_str) {
                if !object.contains_key(name) {
                    return Err(ToolError::InvalidInput(format!(
                        "{path} is missing required property '{name}'"
                    )));
                }
            }
        }

        if let Some(properties) = schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
        {
            for (name, property_schema) in properties {
                if let Some(property) = object.get(name) {
                    validate_schema(property, property_schema, &format!("{path}.{name}"))?;
                }
            }
            if schema.get("additionalProperties") == Some(&serde_json::Value::Bool(false)) {
                for name in object.keys() {
                    if !properties.contains_key(name) {
                        return Err(ToolError::InvalidInput(format!(
                            "{path} contains unadvertised property '{name}'"
                        )));
                    }
                }
            }
        }
    }

    if let (Some(items), Some(values)) = (schema.get("items"), value.as_array()) {
        for (index, item) in values.iter().enumerate() {
            validate_schema(item, items, &format!("{path}[{index}]"))?;
        }
    }

    Ok(())
}

fn value_matches_type(value: &serde_json::Value, expected: &str) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value
            .as_f64()
            .is_some_and(|number| number.is_finite() && number.fract() == 0.0),
        "number" => value.is_number(),
        "null" => value.is_null(),
        _ => false,
    }
}

fn schema_type_label(expected: &serde_json::Value) -> String {
    match expected {
        serde_json::Value::String(expected) => article(expected),
        serde_json::Value::Array(expected) => expected
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(article)
            .collect::<Vec<_>>()
            .join(" or "),
        _ => "a value matching the advertised schema".into(),
    }
}

fn article(kind: &str) -> String {
    let article = if kind.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    };
    format!("{article} {kind}")
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize)]
struct RpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    const fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: serde_json::Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    fn error_with_data(
        id: serde_json::Value,
        code: i64,
        message: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: Some(data),
            }),
        }
    }

    fn into_current(mut self, method: &str, identity: McpServerIdentity<'_>) -> Self {
        if let Some(serde_json::Value::Object(result)) = self.result.as_mut() {
            result
                .entry("resultType")
                .or_insert_with(|| serde_json::Value::String("complete".into()));
            if matches!(method, "server/discover" | "tools/list") {
                result
                    .entry("ttlMs")
                    .or_insert_with(|| serde_json::Value::from(0));
                result
                    .entry("cacheScope")
                    .or_insert_with(|| serde_json::Value::String("private".into()));
            }
            let metadata = result
                .entry("_meta")
                .or_insert_with(|| serde_json::json!({}));
            if let Some(metadata) = metadata.as_object_mut() {
                metadata.insert(
                    "io.modelcontextprotocol/serverInfo".into(),
                    serde_json::json!({
                        "name": identity.name,
                        "version": identity.version,
                    }),
                );
            }
        }
        self
    }

    fn bound_tool_call(self, current: bool, identity: McpServerIdentity<'_>) -> Self {
        let actual_chars = serde_json::to_string(&self)
            .map_or(usize::MAX, |serialized| serialized.chars().count());
        if actual_chars <= MAX_TOOL_RESULT_CHARS {
            return self;
        }

        // The cap belongs to the assembled transport result. Measuring only
        // structuredContent misses JSON-string escaping in legacy text and,
        // historically, counted the same payload twice. Refuse atomically;
        // never emit a prefix that looks like an authoritative typed result.
        let id = self.id;
        let mut bounded = Self::success(
            id,
            tool_call_result(result_too_large_value(actual_chars), true, current),
        );
        if current {
            bounded = bounded.into_current("tools/call", identity);
        }
        debug_assert!(
            serde_json::to_string(&bounded)
                .is_ok_and(|serialized| serialized.chars().count() <= MAX_TOOL_RESULT_CHARS),
            "assembled result-too-large response must obey the final character cap"
        );
        bounded
    }
}

/// Run the line-delimited MCP transport on stdin/stdout.
pub async fn run_stdio(
    dispatcher: std::sync::Arc<dyn McpToolDispatcher>,
    identity: McpServerIdentity<'static>,
) -> Result<(), std::io::Error> {
    let input = tokio::io::BufReader::new(tokio::io::stdin());
    let output = tokio::io::stdout();
    serve(input, output, dispatcher, identity).await
}

/// Generic transport seam used by hermetic protocol tests.
pub async fn serve<R, W>(
    input: R,
    output: W,
    dispatcher: std::sync::Arc<dyn McpToolDispatcher>,
    identity: McpServerIdentity<'static>,
) -> Result<(), std::io::Error>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut input = input;
    let mut output = output;
    let result = serve_loop(
        &mut input,
        &mut output,
        std::sync::Arc::clone(&dispatcher),
        identity,
    )
    .await;
    dispatcher.shutdown().await;
    result
}

enum IncomingRequest {
    Ignore,
    Immediate(JsonRpcResponse),
    Dispatch(JsonRpcRequest),
}

enum ServeEvent {
    Input(Option<IncomingRequest>),
    Completed(Result<(u64, JsonRpcResponse), tokio::task::JoinError>),
}

async fn read_incoming_request<R>(
    input: &mut R,
    line: &mut String,
) -> Result<Option<IncomingRequest>, std::io::Error>
where
    R: AsyncBufRead + Unpin,
{
    line.clear();
    if input.read_line(line).await? == 0 {
        return Ok(None);
    }
    let request: JsonRpcRequest = match serde_json::from_str(line.trim()) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Some(IncomingRequest::Immediate(JsonRpcResponse::error(
                serde_json::Value::Null,
                -32700,
                error.to_string(),
            ))));
        }
    };
    if request.id.is_none() {
        Ok(Some(IncomingRequest::Ignore))
    } else {
        Ok(Some(IncomingRequest::Dispatch(request)))
    }
}

async fn respond_to_request(
    request: JsonRpcRequest,
    dispatcher: &dyn McpToolDispatcher,
    identity: McpServerIdentity<'static>,
) -> JsonRpcResponse {
    let id = request.id.unwrap_or(serde_json::Value::Null);
    if request.jsonrpc != "2.0" {
        return JsonRpcResponse::error(id, -32600, "jsonrpc must be '2.0'");
    }

    let current =
        request.method == "server/discover" || has_current_protocol_marker(request.params.as_ref());
    if current {
        match validate_current_request(request.params.as_ref()) {
            Ok(()) => {
                dispatch_request(
                    id,
                    &request.method,
                    request.params,
                    dispatcher,
                    identity,
                    true,
                )
                .await
            }
            Err(error) => error.with_id(id),
        }
    } else {
        dispatch_request(
            id,
            &request.method,
            request.params,
            dispatcher,
            identity,
            false,
        )
        .await
    }
}

async fn serve_loop<R, W>(
    input: &mut R,
    output: &mut W,
    dispatcher: std::sync::Arc<dyn McpToolDispatcher>,
    identity: McpServerIdentity<'static>,
) -> Result<(), std::io::Error>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut tasks = tokio::task::JoinSet::new();
    let mut completed = std::collections::BTreeMap::new();
    let mut line = String::new();
    let mut input_closed = false;
    let mut next_sequence = 0_u64;
    let mut next_write = 0_u64;

    loop {
        while let Some(response) = completed.remove(&next_write) {
            write_response(&mut *output, &response).await?;
            next_write = next_write.saturating_add(1);
        }
        if input_closed && tasks.is_empty() {
            break;
        }

        let outstanding = next_sequence.saturating_sub(next_write);
        let event = if input_closed || outstanding >= MAX_IN_FLIGHT_REQUESTS {
            ServeEvent::Completed(
                tasks
                    .join_next()
                    .await
                    .expect("an outstanding MCP response task must exist"),
            )
        } else if tasks.is_empty() {
            ServeEvent::Input(read_incoming_request(input, &mut line).await?)
        } else {
            tokio::select! {
                biased;
                completed = tasks.join_next() => ServeEvent::Completed(
                    completed.expect("a tracked MCP response task must exist")
                ),
                incoming = read_incoming_request(input, &mut line) => {
                    ServeEvent::Input(incoming?)
                }
            }
        };

        match event {
            ServeEvent::Input(None) => input_closed = true,
            ServeEvent::Input(Some(IncomingRequest::Ignore)) => {}
            ServeEvent::Input(Some(IncomingRequest::Immediate(response))) => {
                completed.insert(next_sequence, response);
                next_sequence = next_sequence.saturating_add(1);
            }
            ServeEvent::Input(Some(IncomingRequest::Dispatch(request))) => {
                let sequence = next_sequence;
                next_sequence = next_sequence.saturating_add(1);
                let fallback_id = request
                    .id
                    .clone()
                    .expect("dispatch admission requires a request id");
                let dispatcher = std::sync::Arc::clone(&dispatcher);
                tasks.spawn(async move {
                    let response_task = tokio::spawn(async move {
                        respond_to_request(request, dispatcher.as_ref(), identity).await
                    });
                    let response = match response_task.await {
                        Ok(response) => response,
                        Err(error) => JsonRpcResponse::error(
                            fallback_id,
                            -32603,
                            format!("MCP request task failed: {error}"),
                        ),
                    };
                    (sequence, response)
                });
            }
            ServeEvent::Completed(Ok((sequence, response))) => {
                completed.insert(sequence, response);
            }
            ServeEvent::Completed(Err(error)) => {
                return Err(std::io::Error::other(format!(
                    "MCP response coordinator failed: {error}"
                )));
            }
        }
    }
    Ok(())
}

struct RequestError {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

impl RequestError {
    fn with_id(self, id: serde_json::Value) -> JsonRpcResponse {
        match self.data {
            Some(data) => JsonRpcResponse::error_with_data(id, self.code, self.message, data),
            None => JsonRpcResponse::error(id, self.code, self.message),
        }
    }
}

fn has_current_protocol_marker(params: Option<&serde_json::Value>) -> bool {
    params
        .and_then(|params| params.get("_meta"))
        .and_then(serde_json::Value::as_object)
        .is_some_and(|metadata| metadata.contains_key("io.modelcontextprotocol/protocolVersion"))
}

fn validate_current_request(params: Option<&serde_json::Value>) -> Result<(), RequestError> {
    let Some(params) = params.and_then(serde_json::Value::as_object) else {
        return Err(RequestError {
            code: -32602,
            message: "current MCP requests require object params with _meta".into(),
            data: None,
        });
    };
    let Some(metadata) = params.get("_meta").and_then(serde_json::Value::as_object) else {
        return Err(RequestError {
            code: -32602,
            message: "current MCP requests require params._meta".into(),
            data: None,
        });
    };
    let Some(requested) = metadata
        .get("io.modelcontextprotocol/protocolVersion")
        .and_then(serde_json::Value::as_str)
    else {
        return Err(RequestError {
            code: -32602,
            message: "current MCP requests require a protocol version in params._meta".into(),
            data: None,
        });
    };
    if requested != CURRENT_PROTOCOL_VERSION {
        return Err(RequestError {
            code: -32022,
            message: format!("unsupported MCP protocol version '{requested}'"),
            data: Some(serde_json::json!({
                "supported": SUPPORTED_PROTOCOL_VERSIONS,
                "requested": requested,
            })),
        });
    }
    if !metadata
        .get("io.modelcontextprotocol/clientCapabilities")
        .is_some_and(serde_json::Value::is_object)
    {
        return Err(RequestError {
            code: -32602,
            message: "current MCP requests require clientCapabilities in params._meta".into(),
            data: None,
        });
    }
    Ok(())
}

async fn dispatch_request(
    id: serde_json::Value,
    method: &str,
    params: Option<serde_json::Value>,
    dispatcher: &dyn McpToolDispatcher,
    identity: McpServerIdentity<'_>,
    current: bool,
) -> JsonRpcResponse {
    let response = match method {
        "server/discover" if current => JsonRpcResponse::success(
            id,
            serde_json::json!({
                "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
                "capabilities": {"tools": {}},
                "instructions": "Repo-bound structural code intelligence. Use status before precision-sensitive queries and reindex explicitly when stale."
            }),
        ),
        "initialize" if !current => {
            let requested = params
                .as_ref()
                .and_then(|params| params.get("protocolVersion"))
                .and_then(serde_json::Value::as_str);
            let protocol_version = requested
                .filter(|requested| SUPPORTED_PROTOCOL_VERSIONS[1..].contains(requested))
                .unwrap_or(LATEST_LEGACY_PROTOCOL_VERSION);
            JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "protocolVersion": protocol_version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": identity.name, "version": identity.version}
                }),
            )
        }
        "ping" if !current => JsonRpcResponse::success(id, serde_json::json!({})),
        "tools/list" => JsonRpcResponse::success(
            id,
            serde_json::json!({
                "tools": dispatcher.definitions().iter().map(|definition| {
                    serde_json::json!({
                        "name": definition.name,
                        "description": definition.description,
                        "inputSchema": definition.input_schema,
                    })
                }).collect::<Vec<_>>()
            }),
        ),
        "tools/call" => handle_call(id, params, dispatcher, current).await,
        _ => JsonRpcResponse::error(id, -32601, "method not found"),
    };
    let response = if current {
        response.into_current(method, identity)
    } else {
        response
    };
    if method == "tools/call" {
        response.bound_tool_call(current, identity)
    } else {
        response
    }
}

async fn handle_call(
    id: serde_json::Value,
    params: Option<serde_json::Value>,
    dispatcher: &dyn McpToolDispatcher,
    current: bool,
) -> JsonRpcResponse {
    let Some(params) = params else {
        return JsonRpcResponse::error(id, -32602, "missing tools/call params");
    };
    let Some(name) = params.get("name").and_then(serde_json::Value::as_str) else {
        return JsonRpcResponse::error(id, -32602, "missing tools/call name");
    };
    let Some(definition) = dispatcher
        .definitions()
        .iter()
        .find(|definition| definition.name == name)
    else {
        return JsonRpcResponse::error(id, -32602, format!("Unknown tool: {name}"));
    };
    let input = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    if let Err(error) = validate_schema(&input, &definition.input_schema, "arguments") {
        return JsonRpcResponse::error(id, -32602, error.to_string());
    }
    match dispatcher.execute(name, input).await {
        Ok(value) => JsonRpcResponse::success(id, tool_call_result(value, false, current)),
        Err(ToolError::InvalidInput(message)) => {
            JsonRpcResponse::error(id, -32602, format!("Invalid input: {message}"))
        }
        Err(error) => {
            let mut message = error.to_string();
            if let Some(hint) = dispatcher.recovery_hint(name, &error) {
                message.push_str("\nRecovery hint: ");
                message.push_str(&hint);
            }
            let error_value = serde_json::json!({
                "error": error.structured_error_details(message),
            });
            JsonRpcResponse::success(id, tool_call_result(error_value, true, current))
        }
    }
}

fn tool_call_result(value: serde_json::Value, is_error: bool, current: bool) -> serde_json::Value {
    let text = if current && !is_error {
        STRUCTURED_CONTENT_NOTICE.into()
    } else {
        serde_json::to_string(&value)
            .unwrap_or_else(|_| "{\"error\":{\"code\":\"serialization_failed\"}}".into())
    };
    let mut result = serde_json::json!({
        "content": [{"type": "text", "text": text}],
    });
    if current {
        result["structuredContent"] = value;
    }
    if is_error {
        result["isError"] = serde_json::Value::Bool(true);
    }
    result
}

fn result_too_large_value(actual_chars: usize) -> serde_json::Value {
    serde_json::json!({
        "error": {
            "code": "result_too_large",
            "message": format!(
                "assembled tool response is {actual_chars} characters; maximum is {MAX_TOOL_RESULT_CHARS}"
            ),
            "actual_chars": actual_chars,
            "max_chars": MAX_TOOL_RESULT_CHARS,
            "remedy": "Narrow the query, lower its page limit, or request fewer sections."
        }
    })
}

async fn write_response<W: AsyncWrite + Unpin>(
    output: &mut W,
    response: &JsonRpcResponse,
) -> Result<(), std::io::Error> {
    let serialized =
        serde_json::to_vec(response).map_err(|error| std::io::Error::other(error.to_string()))?;
    output.write_all(&serialized).await?;
    output.write_all(b"\n").await?;
    output.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_validation_enforces_advertised_integer_bounds() {
        let schema = serde_json::json!({
            "type": "integer",
            "minimum": 1,
            "maximum": 100
        });
        assert!(validate_schema(&serde_json::json!(1), &schema, "arguments.limit").is_ok());
        assert!(validate_schema(&serde_json::json!(100), &schema, "arguments.limit").is_ok());

        for (value, bound) in [(0, "minimum"), (101, "maximum")] {
            let error = validate_schema(&serde_json::json!(value), &schema, "arguments.limit")
                .expect_err("out-of-range integer must be rejected");
            let message = error.to_string();
            assert!(message.contains("arguments.limit"), "{message}");
            assert!(message.contains(bound), "{message}");
        }
    }

    #[test]
    fn schema_validation_enforces_advertised_string_and_array_bounds() {
        let string_schema = serde_json::json!({
            "type": "string",
            "minLength": 1,
            "maxLength": 3
        });
        assert!(
            validate_schema(&serde_json::json!("abc"), &string_schema, "arguments.name").is_ok()
        );
        for (value, bound) in [("", "minLength"), ("abcd", "maxLength")] {
            let error =
                validate_schema(&serde_json::json!(value), &string_schema, "arguments.name")
                    .expect_err("out-of-range string must be rejected");
            assert!(error.to_string().contains(bound), "{error}");
        }

        let array_schema = serde_json::json!({
            "type": "array",
            "minItems": 1,
            "maxItems": 2,
            "uniqueItems": true,
            "items": {"type": "string"}
        });
        assert!(
            validate_schema(
                &serde_json::json!(["source", "tests"]),
                &array_schema,
                "arguments.sections"
            )
            .is_ok()
        );
        for (value, bound) in [
            (serde_json::json!([]), "minItems"),
            (serde_json::json!(["a", "b", "c"]), "maxItems"),
            (serde_json::json!(["source", "source"]), "uniqueItems"),
        ] {
            let error = validate_schema(&value, &array_schema, "arguments.sections")
                .expect_err("invalid array shape must be rejected");
            assert!(error.to_string().contains(bound), "{error}");
        }
    }

    enum StaticOutcome {
        Success(serde_json::Value),
        DomainError,
    }

    struct StaticDispatcher {
        definitions: Vec<ToolDefinition>,
        outcome: StaticOutcome,
    }

    impl StaticDispatcher {
        fn new(outcome: StaticOutcome) -> Self {
            Self {
                definitions: vec![ToolDefinition {
                    name: "calls".into(),
                    description: "test Calls dispatcher".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "additionalProperties": false
                    }),
                    server_tool_type: None,
                }],
                outcome,
            }
        }
    }

    #[async_trait::async_trait]
    impl McpToolDispatcher for StaticDispatcher {
        fn definitions(&self) -> &[ToolDefinition] {
            &self.definitions
        }

        async fn execute(
            &self,
            _name: &str,
            _input: serde_json::Value,
        ) -> Result<serde_json::Value, ToolError> {
            match &self.outcome {
                StaticOutcome::Success(value) => Ok(value.clone()),
                StaticOutcome::DomainError => Err(ToolError::Domain {
                    message: "Calls capability is unavailable".into(),
                    envelope: serde_json::json!({
                        "error": {
                            "code": "capability_unavailable",
                            "message": "Calls capability is unavailable",
                            "capability": "calls"
                        }
                    }),
                }),
            }
        }
    }

    struct OverlapDispatcher {
        definitions: Vec<ToolDefinition>,
        barrier: tokio::sync::Barrier,
        in_flight: std::sync::atomic::AtomicUsize,
        max_in_flight: std::sync::atomic::AtomicUsize,
    }

    impl OverlapDispatcher {
        fn new() -> Self {
            Self {
                definitions: vec![ToolDefinition {
                    name: "status".into(),
                    description: "concurrent transport probe".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "additionalProperties": false
                    }),
                    server_tool_type: None,
                }],
                barrier: tokio::sync::Barrier::new(2),
                in_flight: std::sync::atomic::AtomicUsize::new(0),
                max_in_flight: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl McpToolDispatcher for OverlapDispatcher {
        fn definitions(&self) -> &[ToolDefinition] {
            &self.definitions
        }

        async fn execute(
            &self,
            _name: &str,
            _input: serde_json::Value,
        ) -> Result<serde_json::Value, ToolError> {
            use std::sync::atomic::Ordering;

            let in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(in_flight, Ordering::SeqCst);
            self.barrier.wait().await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(serde_json::json!({"overlap": true}))
        }
    }

    struct BoundedDispatcher {
        definitions: Vec<ToolDefinition>,
        in_flight: std::sync::atomic::AtomicUsize,
        max_in_flight: std::sync::atomic::AtomicUsize,
        reached_limit: tokio::sync::Notify,
        released: std::sync::atomic::AtomicBool,
        release: tokio::sync::Notify,
    }

    impl BoundedDispatcher {
        fn new() -> Self {
            Self {
                definitions: vec![ToolDefinition {
                    name: "status".into(),
                    description: "bounded transport probe".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "additionalProperties": false
                    }),
                    server_tool_type: None,
                }],
                in_flight: std::sync::atomic::AtomicUsize::new(0),
                max_in_flight: std::sync::atomic::AtomicUsize::new(0),
                reached_limit: tokio::sync::Notify::new(),
                released: std::sync::atomic::AtomicBool::new(false),
                release: tokio::sync::Notify::new(),
            }
        }

        async fn wait_until_released(&self) {
            use std::sync::atomic::Ordering;

            while !self.released.load(Ordering::SeqCst) {
                let released = self.release.notified();
                if self.released.load(Ordering::SeqCst) {
                    break;
                }
                released.await;
            }
        }
    }

    #[async_trait::async_trait]
    impl McpToolDispatcher for BoundedDispatcher {
        fn definitions(&self) -> &[ToolDefinition] {
            &self.definitions
        }

        async fn execute(
            &self,
            _name: &str,
            _input: serde_json::Value,
        ) -> Result<serde_json::Value, ToolError> {
            use std::sync::atomic::Ordering;

            let in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(in_flight, Ordering::SeqCst);
            if in_flight == MAX_IN_FLIGHT_REQUESTS as usize {
                self.reached_limit.notify_one();
            }
            self.wait_until_released().await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(serde_json::json!({"bounded": true}))
        }
    }

    struct PanicDispatcher {
        definitions: Vec<ToolDefinition>,
        shutdowns: std::sync::atomic::AtomicUsize,
    }

    impl PanicDispatcher {
        fn new() -> Self {
            Self {
                definitions: vec![ToolDefinition {
                    name: "status".into(),
                    description: "panic-boundary transport probe".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {"panic": {"type": "boolean"}},
                        "additionalProperties": false
                    }),
                    server_tool_type: None,
                }],
                shutdowns: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl McpToolDispatcher for PanicDispatcher {
        fn definitions(&self) -> &[ToolDefinition] {
            &self.definitions
        }

        async fn execute(
            &self,
            _name: &str,
            input: serde_json::Value,
        ) -> Result<serde_json::Value, ToolError> {
            if input.get("panic").and_then(serde_json::Value::as_bool) == Some(true) {
                panic!("intentional MCP handler crash boundary");
            }
            Ok(serde_json::json!({"healthy": true}))
        }

        async fn shutdown(&self) {
            self.shutdowns
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// FALSIFIER: one MCP connection must be able to execute independent tool
    /// calls concurrently. Responses remain input-ordered so transport
    /// concurrency does not silently change the existing deterministic wire
    /// contract.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stdio_overlaps_tool_execution_and_preserves_response_order() {
        use std::sync::atomic::Ordering;
        use tokio::io::AsyncReadExt;

        let dispatcher = std::sync::Arc::new(OverlapDispatcher::new());
        let (server_stream, client_stream) = tokio::io::duplex(16 * 1024);
        let (server_read, server_write) = tokio::io::split(server_stream);
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let server_dispatcher: std::sync::Arc<dyn McpToolDispatcher> = dispatcher.clone();
        let server = serve(
            tokio::io::BufReader::new(server_read),
            server_write,
            server_dispatcher,
            McpServerIdentity::new("transport-probe", "0.0.0"),
        );
        let client = async move {
            for id in [1, 2] {
                let request = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": {"name": "status", "arguments": {}}
                });
                client_write
                    .write_all(request.to_string().as_bytes())
                    .await
                    .expect("write MCP request");
                client_write
                    .write_all(b"\n")
                    .await
                    .expect("terminate MCP request");
            }
            client_write.shutdown().await.expect("close MCP input");
            let mut output = Vec::new();
            client_read
                .read_to_end(&mut output)
                .await
                .expect("read MCP responses");
            output
        };
        let (server_result, output) =
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                tokio::join!(server, client)
            })
            .await
            .expect("MCP server serialized independent requests");
        server_result.expect("serve concurrent MCP requests");

        let responses = String::from_utf8(output)
            .expect("UTF-8 MCP output")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("MCP response"))
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2, "positive response-population control");
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[1]["id"], 2);
        assert!(
            dispatcher.max_in_flight.load(Ordering::SeqCst) > 1,
            "positive execution-overlap control"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stdio_bounds_execution_and_drains_all_requests_after_eof() {
        use std::sync::atomic::Ordering;
        use tokio::io::AsyncReadExt;

        let dispatcher = std::sync::Arc::new(BoundedDispatcher::new());
        let (server_stream, client_stream) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server_stream);
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let server_dispatcher: std::sync::Arc<dyn McpToolDispatcher> = dispatcher.clone();
        let server = serve(
            tokio::io::BufReader::new(server_read),
            server_write,
            server_dispatcher,
            McpServerIdentity::new("bounded-transport-probe", "0.0.0"),
        );
        let client = async move {
            for id in 1..=40 {
                let request = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": {"name": "status", "arguments": {}}
                });
                client_write
                    .write_all(request.to_string().as_bytes())
                    .await
                    .expect("write bounded MCP request");
                client_write
                    .write_all(b"\n")
                    .await
                    .expect("terminate bounded MCP request");
            }
            client_write.shutdown().await.expect("close bounded input");
            let mut output = Vec::new();
            client_read
                .read_to_end(&mut output)
                .await
                .expect("read bounded MCP responses");
            output
        };
        let release = {
            let dispatcher = std::sync::Arc::clone(&dispatcher);
            async move {
                dispatcher.reached_limit.notified().await;
                dispatcher.released.store(true, Ordering::SeqCst);
                dispatcher.release.notify_waiters();
            }
        };
        let (server_result, output, ()) =
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                tokio::join!(server, client, release)
            })
            .await
            .expect("bounded MCP requests did not drain after EOF");
        server_result.expect("serve bounded MCP requests");

        let responses = String::from_utf8(output)
            .expect("UTF-8 bounded MCP output")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("MCP response"))
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 40, "every admitted request must drain");
        for (expected_id, response) in (1..=40).zip(&responses) {
            assert_eq!(response["id"], expected_id, "ordered response drain");
        }
        assert_eq!(
            dispatcher.max_in_flight.load(Ordering::SeqCst),
            MAX_IN_FLIGHT_REQUESTS as usize,
            "positive concurrency-cap control"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stdio_contains_handler_panic_and_runs_terminal_shutdown_once() {
        use std::sync::atomic::Ordering;
        use tokio::io::AsyncReadExt;

        let dispatcher = std::sync::Arc::new(PanicDispatcher::new());
        let (server_stream, client_stream) = tokio::io::duplex(16 * 1024);
        let (server_read, server_write) = tokio::io::split(server_stream);
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let server_dispatcher: std::sync::Arc<dyn McpToolDispatcher> = dispatcher.clone();
        let server = serve(
            tokio::io::BufReader::new(server_read),
            server_write,
            server_dispatcher,
            McpServerIdentity::new("panic-transport-probe", "0.0.0"),
        );
        let client = async move {
            for (id, should_panic) in [(1, true), (2, false)] {
                let request = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": {
                        "name": "status",
                        "arguments": {"panic": should_panic},
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": CURRENT_PROTOCOL_VERSION,
                            "io.modelcontextprotocol/clientCapabilities": {}
                        }
                    }
                });
                client_write
                    .write_all(request.to_string().as_bytes())
                    .await
                    .expect("write panic-boundary request");
                client_write
                    .write_all(b"\n")
                    .await
                    .expect("terminate request");
            }
            client_write.shutdown().await.expect("close panic input");
            let mut output = Vec::new();
            client_read
                .read_to_end(&mut output)
                .await
                .expect("read panic-boundary responses");
            output
        };
        let (server_result, output) =
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                tokio::join!(server, client)
            })
            .await
            .expect("MCP panic boundary stranded the transport");
        server_result.expect("serve after handler panic");

        let responses = String::from_utf8(output)
            .expect("UTF-8 panic MCP output")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("MCP response"))
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[0]["error"]["code"], -32603);
        assert_eq!(responses[1]["id"], 2);
        assert_eq!(responses[1]["result"]["structuredContent"]["healthy"], true);
        assert_eq!(
            dispatcher.shutdowns.load(Ordering::SeqCst),
            1,
            "terminal dispatcher shutdown must run exactly once"
        );
    }

    async fn call_static(dispatcher: &StaticDispatcher, current: bool) -> serde_json::Value {
        serde_json::to_value(
            dispatch_request(
                serde_json::json!(1),
                "tools/call",
                Some(serde_json::json!({
                    "name": "calls",
                    "arguments": {}
                })),
                dispatcher,
                McpServerIdentity::new("transport-probe", "0.0.0"),
                current,
            )
            .await,
        )
        .expect("serialize test JSON-RPC response")
    }

    #[tokio::test]
    async fn current_results_carry_one_full_structured_payload_and_typed_errors_remain_readable() {
        let success = call_static(
            &StaticDispatcher::new(StaticOutcome::Success(serde_json::json!({
                "schema_version": "h00/code-intel/calls/v1",
                "capability": "calls",
                "items": []
            }))),
            true,
        )
        .await;
        let success_result = &success["result"];
        assert_eq!(
            success_result["content"][0]["text"],
            STRUCTURED_CONTENT_NOTICE
        );
        assert_eq!(
            success_result["structuredContent"]["schema_version"],
            "h00/code-intel/calls/v1"
        );
        assert!(success_result.get("isError").is_none());

        let error = call_static(&StaticDispatcher::new(StaticOutcome::DomainError), true).await;
        let error_result = &error["result"];
        let error_text: serde_json::Value = serde_json::from_str(
            error_result["content"][0]["text"]
                .as_str()
                .expect("error text fallback"),
        )
        .expect("error text JSON");
        assert_eq!(error_text, error_result["structuredContent"]);
        assert_eq!(error_result["isError"], true);
        assert_eq!(
            error_result["structuredContent"]["error"]["code"],
            "capability_unavailable"
        );
    }

    #[tokio::test]
    async fn legacy_results_carry_one_full_json_text_payload_without_duplication() {
        let response = call_static(
            &StaticDispatcher::new(StaticOutcome::Success(serde_json::json!({
                "schema_version": "h00/code-intel/calls/v1",
                "items": [{"callee": "target"}]
            }))),
            false,
        )
        .await;
        let result = &response["result"];
        assert!(result.get("structuredContent").is_none());
        let payload: serde_json::Value = serde_json::from_str(
            result["content"][0]["text"]
                .as_str()
                .expect("legacy JSON text payload"),
        )
        .expect("legacy text must contain the complete typed value");
        assert_eq!(payload["items"][0]["callee"], "target");
    }

    #[tokio::test]
    async fn oversized_calls_result_is_a_typed_error_not_a_truncated_dto_prefix() {
        let response = call_static(
            &StaticDispatcher::new(StaticOutcome::Success(serde_json::json!({
                "schema_version": "h00/code-intel/calls/v1",
                "capability": "calls",
                "items": [{"context": "x".repeat(MAX_TOOL_RESULT_CHARS + 1_000)}]
            }))),
            true,
        )
        .await;
        let result = &response["result"];
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["structuredContent"]["error"]["code"],
            "result_too_large"
        );
        assert!(result["structuredContent"].get("truncated").is_none());
        assert!(result["structuredContent"].get("prefix").is_none());
        let text = result["content"][0]["text"]
            .as_str()
            .expect("bounded text fallback");
        assert!(text.chars().count() <= MAX_TOOL_RESULT_CHARS);
        let text_value: serde_json::Value =
            serde_json::from_str(text).expect("typed oversize error JSON");
        assert_eq!(text_value, result["structuredContent"]);
    }

    #[test]
    fn over_cap_values_become_typed_errors_within_the_final_character_cap() {
        let identity = McpServerIdentity::new("transport-probe", "0.0.0");
        let response = JsonRpcResponse::success(
            serde_json::json!(1),
            tool_call_result(
                serde_json::json!({"body": "x".repeat(MAX_TOOL_RESULT_CHARS + 1_000)}),
                false,
                true,
            ),
        )
        .into_current("tools/call", identity)
        .bound_tool_call(true, identity);
        let value = serde_json::to_value(&response).expect("bounded response value");
        assert_eq!(
            value["result"]["structuredContent"]["error"]["code"],
            "result_too_large"
        );
        assert!(value["result"]["structuredContent"].get("prefix").is_none());
        assert!(
            value["result"]["structuredContent"]["error"]["actual_chars"]
                .as_u64()
                .unwrap()
                > u64::try_from(MAX_TOOL_RESULT_CHARS).expect("transport limit fits u64")
        );
        let serialized = serde_json::to_string(&response).expect("bounded response JSON");
        assert!(
            serialized.chars().count() <= MAX_TOOL_RESULT_CHARS,
            "the assembled MCP response must obey the advertised cap; got {}",
            serialized.chars().count()
        );
    }

    #[test]
    fn domain_bounded_legacy_escaped_value_survives_the_transport_envelope() {
        let identity = McpServerIdentity::new("transport-probe", "0.0.0");
        let body = "\\".repeat(13_000);
        let value = serde_json::json!({"body": body});
        assert!(
            serde_json::to_string(&value)
                .expect("domain value JSON")
                .chars()
                .count()
                <= h00ligan_engine::code_intel_domain::MAX_CODE_INTEL_RESULT_CHARS,
            "known-positive control: the typed value must fit the domain envelope"
        );
        let response = JsonRpcResponse::success(
            serde_json::json!(1),
            tool_call_result(value.clone(), false, false),
        )
        .bound_tool_call(false, identity);
        let response_value = serde_json::to_value(&response).expect("bounded escaped response");
        assert_ne!(response_value["result"]["isError"], true);
        let text: serde_json::Value = serde_json::from_str(
            response_value["result"]["content"][0]["text"]
                .as_str()
                .expect("complete legacy result text"),
        )
        .expect("complete typed legacy JSON");
        assert_eq!(text, value);
    }

    #[test]
    fn escaping_overhead_is_included_in_the_final_character_cap() {
        let identity = McpServerIdentity::new("transport-probe", "0.0.0");
        let response = JsonRpcResponse::success(
            serde_json::json!(1),
            tool_call_result(
                serde_json::json!({"body": "\\".repeat(MAX_TOOL_RESULT_CHARS / 3)}),
                false,
                false,
            ),
        )
        .bound_tool_call(false, identity);
        let value = serde_json::to_value(&response).expect("bounded escaped response");
        let text: serde_json::Value = serde_json::from_str(
            value["result"]["content"][0]["text"]
                .as_str()
                .expect("bounded legacy error text"),
        )
        .expect("typed legacy error JSON");
        assert_eq!(text["error"]["code"], "result_too_large");
        let serialized = serde_json::to_string(&response).expect("bounded escaped response JSON");
        assert!(
            serialized.chars().count() <= MAX_TOOL_RESULT_CHARS,
            "JSON string escaping must not expand the assembled response beyond the cap; got {}",
            serialized.chars().count()
        );
    }
}

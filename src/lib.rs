//! mcp-wire library: MCP JSON-RPC dispatch and the Wireshark tool
//! implementations shared by the `mcp-wire` binary.
//!
//! The server speaks JSON-RPC 2.0 as newline-delimited JSON on stdio
//! (the MCP stdio transport), following the chat-mcp 0.1.0 pattern.
//! All logging goes to stderr; stdout is the protocol and must never
//! carry anything else.
//!
//! Transport is stdio and local-only, so v1 has no auth. The tools
//! shell out to tshark by direct exec with an argv array — see
//! [`tshark`] for the security model.

pub mod tshark;

pub use tshark::resolve_tshark;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tshark::{
    tool_analyze_pcap, tool_capture, tool_interfaces, validate_display_filter,
    validate_interface_name, validate_pcap_path, DEFAULT_CAPTURE_COUNT, DEFAULT_PCAP_LIMIT,
    PCAP_DIR_ENV,
};

/// Server configuration: an optional tshark override (`--tshark` flag
/// or `TSHARK_PATH`). `None` means "search PATH at call time".
#[derive(Debug, Clone, Default)]
pub struct ServerConfig {
    pub tshark_path: Option<PathBuf>,
}

impl ServerConfig {
    pub fn new(tshark_path: Option<PathBuf>) -> Self {
        Self { tshark_path }
    }

    /// The `MCP_WIRE_PCAP_DIR` scope for `analyze_pcap`, when set.
    fn pcap_dir(&self) -> Option<PathBuf> {
        std::env::var(PCAP_DIR_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
    }
}

/// One MCP tool description, as returned by `tools/list`.
#[derive(Debug, Clone, Serialize)]
pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

fn schema(props: serde_json::Value, required: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": props,
        "required": required,
    })
}

/// The three tools, in the order `tools/list` returns them.
pub fn tool_list() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "capture",
            description: "Live packet capture on an interface via tshark. Returns packet summaries (number, time, src, dst, protocol, length, info) — never raw packet bytes. Stops at `count` packets or after `duration_secs`, whichever comes first; defaults to 10 packets. Needs capture privileges (wireshark group or root) — a permission failure is returned as a tool error.",
            input_schema: schema(
                serde_json::json!({
                    "interface": {"type": "string", "description": "Capture interface name, e.g. eth0, enp0s3, lo, any"},
                    "filter": {"type": "string", "description": "Wireshark display filter, e.g. 'tcp.port == 80'; empty means no filter"},
                    "count": {"type": "integer", "description": "Stop after this many packets; defaults to 10, clamped 1..=1000"},
                    "duration_secs": {"type": "integer", "description": "Stop after this many seconds; 0 means no time cap, clamped 0..=300"},
                }),
                &["interface"],
            ),
        },
        ToolDef {
            name: "analyze_pcap",
            description: "Read a pcap/pcapng file via tshark and return packet summaries (same shape as `capture`). Reading a file needs no capture privileges. Paths are canonicalized and must end in .pcap, .pcapng, or .cap; when MCP_WIRE_PCAP_DIR is set, the file must resolve inside it.",
            input_schema: schema(
                serde_json::json!({
                    "path": {"type": "string", "description": "Path to the pcap/pcapng file"},
                    "filter": {"type": "string", "description": "Wireshark display filter; empty means no filter"},
                    "limit": {"type": "integer", "description": "Max packets to return; defaults to 50, clamped 1..=500"},
                }),
                &["path"],
            ),
        },
        ToolDef {
            name: "interfaces",
            description: "Full detail on every capture interface: name, description, MAC, MTU, operstate, speed, link-layer type, IP addresses, and supported data-link types. Anything unavailable on this host is null with a note explaining why.",
            input_schema: schema(serde_json::json!({}), &[]),
        },
    ]
}

/// A tool result: one text block plus optional structured content.
/// Errors are results with `is_error` set, not protocol errors — the
/// MCP-idiomatic shape for a tool that ran and failed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub content: Vec<ToolContent>,
    #[serde(rename = "structuredContent", skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<serde_json::Value>,
    #[serde(rename = "isError", skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolContent {
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
}

fn tool_ok_text(text: String, structured: Option<serde_json::Value>) -> ToolResult {
    ToolResult {
        content: vec![ToolContent {
            kind: "text".to_string(),
            text,
        }],
        structured_content: structured,
        is_error: false,
    }
}

fn tool_ok_json(value: serde_json::Value) -> ToolResult {
    let text = serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string());
    tool_ok_text(text, Some(value))
}

fn tool_err(text: String) -> ToolResult {
    ToolResult {
        content: vec![ToolContent {
            kind: "text".to_string(),
            text,
        }],
        structured_content: None,
        is_error: true,
    }
}

// ---------------------------------------------------------------------------
// Tool argument helpers
// ---------------------------------------------------------------------------

fn arg_str<'a>(
    args: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    default: &'a str,
) -> Result<&'a str, String> {
    match args.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(serde_json::Value::String(s)) => Ok(s.as_str()),
        Some(_) => Err(format!("argument '{key}' must be a string")),
    }
}

fn arg_i64(
    args: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    default: i64,
) -> Result<i64, String> {
    match args.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(serde_json::Value::Number(n)) => n
            .as_i64()
            .ok_or_else(|| format!("argument '{key}' must be an integer")),
        Some(_) => Err(format!("argument '{key}' must be an integer")),
    }
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

async fn dispatch_tool(cfg: &ServerConfig, name: &str, args: &serde_json::Value) -> ToolResult {
    let empty = serde_json::Map::new();
    let args: &serde_json::Map<String, serde_json::Value> = match args {
        serde_json::Value::Object(map) => map,
        serde_json::Value::Null => &empty,
        _ => return tool_err("arguments must be an object".to_string()),
    };
    match dispatch_inner(cfg, name, args).await {
        Ok(result) => result,
        Err(message) => tool_err(message),
    }
}

async fn dispatch_inner(
    cfg: &ServerConfig,
    name: &str,
    args: &serde_json::Map<String, serde_json::Value>,
) -> Result<ToolResult, String> {
    match name {
        "capture" => {
            let interface = arg_str(args, "interface", "")?;
            let filter = arg_str(args, "filter", "")?;
            let count = arg_i64(args, "count", DEFAULT_CAPTURE_COUNT)?;
            let duration_secs = arg_i64(args, "duration_secs", 0)?;
            validate_interface_name(interface)?;
            validate_display_filter(filter)?;
            let tshark = resolve_tshark(cfg.tshark_path.as_deref())?;
            let value = tool_capture(&tshark, interface, filter, count, duration_secs).await?;
            Ok(tool_ok_json(value))
        }
        "analyze_pcap" => {
            let path = arg_str(args, "path", "")?;
            let filter = arg_str(args, "filter", "")?;
            let limit = arg_i64(args, "limit", DEFAULT_PCAP_LIMIT)?;
            // Validate arguments before resolving tshark, so a bad
            // path reports as a validation error even when tshark is
            // missing (tool_analyze_pcap re-validates before use).
            validate_pcap_path(path, cfg.pcap_dir().as_deref())?;
            validate_display_filter(filter)?;
            let tshark = resolve_tshark(cfg.tshark_path.as_deref())?;
            let value =
                tool_analyze_pcap(&tshark, path, filter, limit, cfg.pcap_dir().as_deref()).await?;
            Ok(tool_ok_json(value))
        }
        "interfaces" => {
            let tshark = resolve_tshark(cfg.tshark_path.as_deref())?;
            let value = tool_interfaces(&tshark).await?;
            Ok(tool_ok_json(value))
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC over stdio
// ---------------------------------------------------------------------------

fn rpc_ok(id: &serde_json::Value, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_err(id: &serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Handle one input line. Returns `None` for notifications (no
/// response) and `Some(response)` for requests.
pub async fn handle_line(cfg: &ServerConfig, line: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            return Some(rpc_err(
                &serde_json::Value::Null,
                -32700,
                "Parse error",
            ))
        }
    };
    let obj = match value.as_object() {
        Some(o) => o,
        None => {
            return Some(rpc_err(
                &serde_json::Value::Null,
                -32600,
                "Invalid Request",
            ))
        }
    };
    // No id (or null id) means a notification: no response, ever.
    let id = match obj.get("id") {
        None | Some(serde_json::Value::Null) => return None,
        Some(id) => id.clone(),
    };
    let method = match obj.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => {
            return Some(rpc_err(&id, -32600, "Invalid Request: missing method"));
        }
    };
    if method.starts_with("notifications/") {
        return None;
    }
    let params = obj.get("params").cloned().unwrap_or(serde_json::Value::Null);
    match method {
        "initialize" => Some(rpc_ok(
            &id,
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mcp-wire", "version": env!("CARGO_PKG_VERSION") },
            }),
        )),
        "ping" => Some(rpc_ok(&id, serde_json::json!({}))),
        "tools/list" => {
            let tools: Vec<serde_json::Value> = tool_list()
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                    })
                })
                .collect();
            Some(rpc_ok(&id, serde_json::json!({ "tools": tools })))
        }
        "tools/call" => {
            let params_obj = params.as_object();
            let name = params_obj
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str());
            let name = match name {
                Some(n) => n,
                None => {
                    return Some(rpc_err(
                        &id,
                        -32602,
                        "Invalid params: tools/call requires params.name",
                    ))
                }
            };
            let args = params_obj
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let result = dispatch_tool(cfg, name, &args).await;
            let result = serde_json::to_value(&result).unwrap_or_else(|_| {
                serde_json::json!({
                    "content": [{ "type": "text", "text": "internal error serializing tool result" }],
                    "isError": true,
                })
            });
            Some(rpc_ok(&id, result))
        }
        _ => Some(rpc_err(&id, -32601, "Method not found")),
    }
}

/// The stdio loop: read lines, dispatch, write one response line per
/// request, flush after each. EOF on stdin exits 0. Logging, if any,
/// must go to stderr — stdout is the protocol.
pub async fn run_stdio(cfg: ServerConfig) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();
    loop {
        let line = match reader.next_line().await {
            Ok(Some(line)) => line,
            _ => break, // EOF or read error: exit quietly
        };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = handle_line(&cfg, &line).await {
            let mut out = serde_json::to_string(&response).unwrap_or_else(|_| {
                "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}"
                    .to_string()
            });
            out.push('\n');
            if stdout.write_all(out.as_bytes()).await.is_err() {
                break;
            }
            if stdout.flush().await.is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bogus_cfg() -> ServerConfig {
        ServerConfig::new(Some(PathBuf::from("/nonexistent/tshark")))
    }

    #[test]
    fn tool_list_names_all_three_tools() {
        let names: Vec<&str> = tool_list().iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["capture", "analyze_pcap", "interfaces"]);
    }

    #[tokio::test]
    async fn protocol_initialize_list_ping_errors() {
        let cfg = bogus_cfg();
        // initialize
        let resp = handle_line(
            &cfg,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        )
        .await
        .unwrap();
        assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(resp["result"]["serverInfo"]["name"], "mcp-wire");
        // tools/list
        let resp = handle_line(&cfg, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .await
            .unwrap();
        assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 3);
        // ping
        let resp = handle_line(&cfg, r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#)
            .await
            .unwrap();
        assert_eq!(resp["result"], serde_json::json!({}));
        // unknown method
        let resp = handle_line(&cfg, r#"{"jsonrpc":"2.0","id":4,"method":"bogus/method"}"#)
            .await
            .unwrap();
        assert_eq!(resp["error"]["code"], -32601);
        // malformed line
        let resp = handle_line(&cfg, "this is not json").await.unwrap();
        assert_eq!(resp["error"]["code"], -32700);
        assert!(resp["id"].is_null());
        // notification: no response
        let resp = handle_line(
            &cfg,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )
        .await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn tools_call_missing_name_is_protocol_error() {
        let cfg = bogus_cfg();
        let resp = handle_line(
            &cfg,
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{}}"#,
        )
        .await
        .unwrap();
        assert_eq!(resp["error"]["code"], -32602);
    }

    #[tokio::test]
    async fn unknown_tool_is_error_not_protocol_error() {
        let cfg = bogus_cfg();
        let resp = handle_line(
            &cfg,
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
        )
        .await
        .unwrap();
        assert!(resp["error"].is_null(), "unknown tool is a tool error: {resp}");
        assert_eq!(resp["result"]["isError"], true);
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown tool"));
    }

    #[tokio::test]
    async fn tshark_missing_is_tool_error_naming_tshark() {
        let cfg = bogus_cfg();
        let resp = handle_line(
            &cfg,
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"interfaces","arguments":{}}}"#,
        )
        .await
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("tshark"), "missing-tshark error names tshark: {text}");
    }

    #[tokio::test]
    async fn bad_interface_name_rejected_before_tshark() {
        let cfg = bogus_cfg();
        let resp = handle_line(
            &cfg,
            r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"capture","arguments":{"interface":"eth0; rm -rf /","count":5}}}"#,
        )
        .await
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("invalid interface name"),
            "validation error names the problem: {text}"
        );
    }

    #[tokio::test]
    async fn bad_pcap_path_rejected_before_tshark() {
        let cfg = bogus_cfg();
        let resp = handle_line(
            &cfg,
            r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"analyze_pcap","arguments":{"path":"/tmp/evil;id.pcap"}}}"#,
        )
        .await
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("must not contain"),
            "path validation error names the problem: {text}"
        );
    }

    // -- stub tshark: verifies the happy path end to end without a real
    // tshark install. The stub is a shell script answering --version,
    // -D, -L, and -T json with canned output. Unix only.
    #[cfg(unix)]
    mod stub_tests {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);

        const STUB: &str = r#"#!/bin/sh
# stub tshark for mcp-wire tests: canned answers, no real capture.
if [ "$1" = "--version" ]; then
  echo "TShark (Wireshark) 4.2.0 (stub)"
  exit 0
fi
for a in "$@"; do
  if [ "$a" = "-D" ]; then
    printf '1. eth0 (Ethernet)\n2. lo (Loopback)\n'
    exit 0
  fi
  if [ "$a" = "-L" ]; then
    printf 'Data link types (use option -y to set):\n  LINKTYPE_ETHERNET\n  LINKTYPE_RAW\n'
    exit 0
  fi
done
cat <<'EOF'
[{"_index":"packets-1","_type":"pcap_file","_score":null,"_source":{"layers":{"frame":{"frame.number":["1"],"frame.time_epoch":["1700000000.123456"],"frame.len":["74"],"frame.protocols":["eth:ethertype:ip:tcp"]},"eth":{"eth.src":["aa:bb:cc:dd:ee:ff"],"eth.dst":["11:22:33:44:55:66"]},"ip":{"ip.src":["10.0.0.1"],"ip.dst":["10.0.0.2"]},"_ws.col":{"_ws.col.Protocol":["TCP"],"_ws.col.Info":["443 → 12345 [SYN]"]}}}}]
EOF
exit 0
"#;

        fn stub_tshark() -> PathBuf {
            let n = NEXT.fetch_add(1, Ordering::SeqCst);
            let dir = PathBuf::from(format!("target/test-stub-{n}"));
            std::fs::create_dir_all(&dir).unwrap();
            let p = dir.join("tshark");
            std::fs::write(&p, STUB).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            p
        }

        fn stub_cfg() -> ServerConfig {
            ServerConfig::new(Some(stub_tshark()))
        }

        fn text_of(resp: &serde_json::Value) -> &str {
            resp["result"]["content"][0]["text"].as_str().unwrap()
        }

        #[tokio::test]
        async fn interfaces_via_stub() {
            let cfg = stub_cfg();
            let resp = handle_line(
                &cfg,
                r#"{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"interfaces","arguments":{}}}"#,
            )
            .await
            .unwrap();
            assert!(
                !resp["result"]["isError"].as_bool().unwrap_or(false),
                "interfaces failed: {resp}"
            );
            let value: serde_json::Value = serde_json::from_str(text_of(&resp)).unwrap();
            let ifaces = value["interfaces"].as_array().unwrap();
            assert_eq!(ifaces.len(), 2);
            assert_eq!(ifaces[0]["name"], "eth0");
            assert_eq!(ifaces[0]["description"], "Ethernet");
            assert_eq!(ifaces[1]["name"], "lo");
            assert_eq!(ifaces[1]["description"], "Loopback");
            // lo exists on this host: its OS details are filled in.
            assert_eq!(ifaces[1]["mac"], "00:00:00:00:00:00");
            // Link-layer types come from the stub's -L answer.
            assert_eq!(ifaces[0]["link_layer_types"][0], "LINKTYPE_ETHERNET");
        }

        #[tokio::test]
        async fn capture_via_stub() {
            let cfg = stub_cfg();
            let resp = handle_line(
                &cfg,
                r#"{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"capture","arguments":{"interface":"eth0","filter":"tcp.port == 443","count":5}}}"#,
            )
            .await
            .unwrap();
            assert!(
                !resp["result"]["isError"].as_bool().unwrap_or(false),
                "capture failed: {resp}"
            );
            let value: serde_json::Value = serde_json::from_str(text_of(&resp)).unwrap();
            assert_eq!(value["interface"], "eth0");
            assert_eq!(value["filter"], "tcp.port == 443");
            assert_eq!(value["captured"], 1);
            let pkt = &value["packets"][0];
            assert_eq!(pkt["src"], "10.0.0.1");
            assert_eq!(pkt["dst"], "10.0.0.2");
            assert_eq!(pkt["protocol"], "TCP");
        }

        #[tokio::test]
        async fn analyze_pcap_via_stub() {
            let dir = PathBuf::from("target/test-data");
            std::fs::create_dir_all(&dir).unwrap();
            let pcap = dir.join("stub-test.pcap");
            std::fs::write(&pcap, b"\xd4\xc3\xb2\xa1").unwrap();
            let cfg = stub_cfg();
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{{"name":"analyze_pcap","arguments":{{"path":{},"filter":"tcp","limit":10}}}}}}"#,
                serde_json::to_string(pcap.to_str().unwrap()).unwrap()
            );
            let resp = handle_line(&cfg, &line).await.unwrap();
            assert!(
                !resp["result"]["isError"].as_bool().unwrap_or(false),
                "analyze failed: {resp}"
            );
            let value: serde_json::Value = serde_json::from_str(text_of(&resp)).unwrap();
            assert_eq!(value["count"], 1);
            assert_eq!(value["packets"][0]["src"], "10.0.0.1");
        }
    }

    // Keep the clamps import honest: these constants shape the schemas.
    #[test]
    fn clamps_are_sane() {
        use crate::tshark::{MAX_CAPTURE_COUNT, MAX_CAPTURE_DURATION_SECS, MAX_PCAP_LIMIT};
        assert!(MAX_CAPTURE_COUNT >= DEFAULT_CAPTURE_COUNT);
        assert!(MAX_CAPTURE_DURATION_SECS > 0);
        assert!(MAX_PCAP_LIMIT >= DEFAULT_PCAP_LIMIT);
    }
}

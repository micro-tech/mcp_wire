//! End-to-end tests for mcp-wire: the real binary, driven over stdio
//! pipes with JSON-RPC, against a stub tshark (canned answers, no
//! real capture, no privileges needed). tshark is not installed in
//! the sandbox, so the stub is the only way to exercise the happy
//! path here — a live smoke test against real tshark is still owed
//! on a host that has it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, Command};
use tokio::time::{timeout, Duration};

static NEXT: AtomicUsize = AtomicUsize::new(0);

const STUB: &str = r#"#!/bin/sh
# stub tshark for mcp-wire e2e tests: canned answers, no real capture.
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
    let dir = PathBuf::from(format!("target/e2e-stub-{n}"));
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

fn mcp_bin() -> String {
    std::env::var("CARGO_BIN_EXE_mcp_wire")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_mcp-wire"))
        .expect("cargo test must set CARGO_BIN_EXE for the mcp-wire binary")
}

/// A running mcp-wire child plus its stdio pipes.
struct McpSession {
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<tokio::process::ChildStdout>>,
    next_id: u64,
}

impl McpSession {
    async fn spawn(tshark: Option<&PathBuf>) -> McpSession {
        let mut cmd = Command::new(mcp_bin());
        if let Some(t) = tshark {
            cmd.arg("--tshark").arg(t);
        }
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn mcp-wire");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        McpSession {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
            next_id: 1,
        }
    }

    async fn request(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        let line = serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
            .to_string();
        self.write_line(&line).await;
        self.read_response().await
    }

    async fn call(&mut self, name: &str, args: serde_json::Value) -> serde_json::Value {
        let resp = self
            .request(
                "tools/call",
                serde_json::json!({"name": name, "arguments": args}),
            )
            .await;
        assert!(
            resp.get("error").is_none(),
            "protocol error on tools/call {name}: {resp}"
        );
        resp["result"].clone()
    }

    async fn notify(&mut self, method: &str, params: serde_json::Value) {
        let line = serde_json::json!({"jsonrpc":"2.0","method":method,"params":params}).to_string();
        self.write_line(&line).await;
    }

    async fn write_line(&mut self, line: &str) {
        self.stdin.write_all(line.as_bytes()).await.unwrap();
        self.stdin.write_all(b"\n").await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    async fn read_response(&mut self) -> serde_json::Value {
        let line = timeout(Duration::from_secs(60), self.lines.next_line())
            .await
            .expect("timed out waiting for an MCP response")
            .expect("MCP stdout failed")
            .expect("MCP server closed stdout");
        serde_json::from_str(&line).expect("server wrote invalid JSON")
    }

    async fn try_read_line(&mut self, dur: Duration) -> Option<String> {
        match timeout(dur, self.lines.next_line()).await {
            Ok(Ok(Some(line))) => Some(line),
            _ => None,
        }
    }

    async fn shutdown(mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

fn init_params() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    })
}

fn text_of(result: &serde_json::Value) -> &str {
    result["content"][0]["text"].as_str().expect("text block")
}

fn is_error(result: &serde_json::Value) -> bool {
    result["isError"].as_bool().unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread")]
async fn initialize_and_list_tools() {
    let stub = stub_tshark();
    let mut mcp = McpSession::spawn(Some(&stub)).await;
    let init = mcp.request("initialize", init_params()).await;
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(init["result"]["serverInfo"]["name"], "mcp-wire");
    let list = mcp.request("tools/list", serde_json::json!({})).await;
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["capture", "analyze_pcap", "interfaces"]);
    mcp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn interfaces_and_capture_via_stub() {
    let stub = stub_tshark();
    let mut mcp = McpSession::spawn(Some(&stub)).await;
    mcp.request("initialize", init_params()).await;

    let ifaces = mcp.call("interfaces", serde_json::json!({})).await;
    assert!(!is_error(&ifaces), "interfaces failed: {ifaces}");
    let value: serde_json::Value = serde_json::from_str(text_of(&ifaces)).unwrap();
    assert_eq!(value["interfaces"].as_array().unwrap().len(), 2);
    assert_eq!(value["interfaces"][0]["name"], "eth0");

    let cap = mcp
        .call(
            "capture",
            serde_json::json!({"interface": "eth0", "count": 5}),
        )
        .await;
    assert!(!is_error(&cap), "capture failed: {cap}");
    let value: serde_json::Value = serde_json::from_str(text_of(&cap)).unwrap();
    assert_eq!(value["captured"], 1);
    assert_eq!(value["packets"][0]["src"], "10.0.0.1");

    let dir = PathBuf::from("target/test-data");
    std::fs::create_dir_all(&dir).unwrap();
    let pcap = dir.join("e2e.pcap");
    std::fs::write(&pcap, b"\xd4\xc3\xb2\xa1").unwrap();
    let ana = mcp
        .call(
            "analyze_pcap",
            serde_json::json!({"path": pcap.to_str().unwrap(), "limit": 10}),
        )
        .await;
    assert!(!is_error(&ana), "analyze_pcap failed: {ana}");
    let value: serde_json::Value = serde_json::from_str(text_of(&ana)).unwrap();
    assert_eq!(value["count"], 1);
    mcp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_interface_name_is_error() {
    let stub = stub_tshark();
    let mut mcp = McpSession::spawn(Some(&stub)).await;
    mcp.request("initialize", init_params()).await;
    let bad = mcp
        .call(
            "capture",
            serde_json::json!({"interface": "eth0; id", "count": 5}),
        )
        .await;
    assert!(is_error(&bad), "metachar interface should be isError: {bad}");
    assert!(text_of(&bad).contains("invalid interface name"));
    mcp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_tshark_is_error_naming_tshark() {
    // No --tshark flag and no real tshark on PATH in the sandbox.
    let mut mcp = McpSession::spawn(None).await;
    mcp.request("initialize", init_params()).await;
    let res = mcp.call("interfaces", serde_json::json!({})).await;
    assert!(is_error(&res), "missing tshark should be isError: {res}");
    assert!(
        text_of(&res).contains("tshark"),
        "error names tshark: {res}"
    );
    mcp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_tool_method_malformed_and_notification() {
    let stub = stub_tshark();
    let mut mcp = McpSession::spawn(Some(&stub)).await;
    mcp.request("initialize", init_params()).await;
    let unknown = mcp.call("nope", serde_json::json!({})).await;
    assert!(is_error(&unknown));
    assert!(text_of(&unknown).contains("unknown tool"));
    let bad_method = mcp.request("bogus/method", serde_json::json!({})).await;
    assert_eq!(bad_method["error"]["code"], -32601);
    // Malformed line: -32700 with null id, then the server still works.
    mcp.write_line("this is not json").await;
    let malformed = mcp.read_response().await;
    assert_eq!(malformed["error"]["code"], -32700);
    assert!(malformed["id"].is_null());
    // Notification: no response.
    mcp.notify("notifications/initialized", serde_json::json!({}))
        .await;
    let extra = mcp.try_read_line(Duration::from_millis(500)).await;
    assert!(extra.is_none(), "notification got a response: {extra:?}");
    let ping = mcp.request("ping", serde_json::json!({})).await;
    assert_eq!(ping["result"], serde_json::json!({}));
    mcp.shutdown().await;
}

//! tshark/dumpcap invocation, argument validation, and output parsing.
//!
//! Security model (non-negotiable):
//! - tshark is always invoked by direct exec with an argv array. No
//!   argument is ever interpolated into a shell string; there is no
//!   shell anywhere in this module.
//! - Interface names are whitelisted to `[A-Za-z0-9_.\-@]` (max 64
//!   chars, never starting with `-`, so a value can never be mistaken
//!   for a tshark flag).
//! - Display filters are checked for NUL/newline characters and a
//!   length cap, then passed as a single argv element.
//! - pcap paths are canonicalized, must be regular files with a
//!   `.pcap`/`.pcapng`/`.cap` extension, and — when `MCP_WIRE_PCAP_DIR`
//!   is set — must resolve inside that directory. Shell metacharacters
//!   in a path are rejected outright.
//! - Live capture needs privileges (member of the `wireshark` group or
//!   root). This code never escalates; a permission failure from
//!   tshark is returned as a tool error naming the problem.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command as TokioCommand;

/// Env var overriding the tshark binary path.
pub const TSHARK_PATH_ENV: &str = "TSHARK_PATH";
/// Env var scoping `analyze_pcap` to one directory tree (optional).
/// When set, pcap paths must canonicalize inside it.
pub const PCAP_DIR_ENV: &str = "MCP_WIRE_PCAP_DIR";

/// Default packet count for `capture` when neither count nor duration
/// is given (an unbounded capture is never the default).
pub const DEFAULT_CAPTURE_COUNT: i64 = 10;
/// Hard cap on packets per `capture` call.
pub const MAX_CAPTURE_COUNT: i64 = 1000;
/// Hard cap on `capture` duration, in seconds.
pub const MAX_CAPTURE_DURATION_SECS: i64 = 300;
/// Default packet limit for `analyze_pcap`.
pub const DEFAULT_PCAP_LIMIT: i64 = 50;
/// Hard cap on packets per `analyze_pcap` call.
pub const MAX_PCAP_LIMIT: i64 = 500;
/// Max display-filter length, in characters.
pub const MAX_FILTER_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// tshark resolution
// ---------------------------------------------------------------------------

/// Error text when tshark cannot be found. Names the binary and where
/// to get it. Tools return this as an `isError` result; the server
/// never crashes over a missing tshark.
pub fn tshark_missing_error() -> String {
    "tshark is not installed or not on PATH. Install Wireshark/tshark \
     (https://www.wireshark.org/download.html) and make sure `tshark` is \
     on PATH, or set TSHARK_PATH to the tshark binary."
        .to_string()
}

/// Resolve the tshark binary: an explicit override (`--tshark` flag,
/// then `TSHARK_PATH`) wins; otherwise search PATH. A bare program
/// name with no path separator is also looked up on PATH.
pub fn resolve_tshark(override_path: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = override_path {
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
        if p.components().count() == 1 {
            if let Some(found) = search_path(&p.to_string_lossy()) {
                return Ok(found);
            }
        }
        return Err(format!(
            "tshark not found at override path {}: {}",
            p.display(),
            tshark_missing_error()
        ));
    }
    if let Ok(env_path) = std::env::var(TSHARK_PATH_ENV) {
        let p = PathBuf::from(env_path.trim());
        if !p.as_os_str().is_empty() {
            if p.is_file() {
                return Ok(p);
            }
            if p.components().count() == 1 {
                if let Some(found) = search_path(&p.to_string_lossy()) {
                    return Ok(found);
                }
            }
            // A set-but-bogus TSHARK_PATH falls through to the PATH
            // search, so a typo does not break a working install; the
            // error below still names tshark.
        }
    }
    if let Some(found) = search_path("tshark") {
        return Ok(found);
    }
    Err(tshark_missing_error())
}

/// Look for an executable program on PATH.
pub fn search_path(prog: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(prog);
        if cand.is_file() && is_executable(&cand) {
            return Some(cand);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

/// Validate a capture interface name. Whitelist only: ASCII letters,
/// digits, `_`, `-`, `.`, `@` (for names like `eth0@if2`), max 64
/// chars, never starting with `-` (flag injection), never `.`/`..`.
pub fn validate_interface_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("interface name must not be empty".to_string());
    }
    if name.len() > 64 {
        return Err("interface name too long (max 64 characters)".to_string());
    }
    if name.starts_with('-') {
        return Err(format!(
            "invalid interface name {name:?}: must not start with '-'"
        ));
    }
    if name == "." || name == ".." {
        return Err(format!("invalid interface name {name:?}"));
    }
    for c in name.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@')) {
            return Err(format!(
                "invalid interface name {name:?}: character {c:?} is not allowed"
            ));
        }
    }
    Ok(())
}

/// Validate a Wireshark display filter. It is passed to tshark as one
/// argv element (never through a shell), so the check is only about
/// control characters and length.
pub fn validate_display_filter(filter: &str) -> Result<(), String> {
    if filter.len() > MAX_FILTER_LEN {
        return Err(format!(
            "display filter too long (max {MAX_FILTER_LEN} characters)"
        ));
    }
    if filter.contains('\0') || filter.contains('\n') || filter.contains('\r') {
        return Err("display filter must not contain NUL or newline characters".to_string());
    }
    Ok(())
}

/// Characters that must never appear in a pcap path (shell
/// metacharacters). Spaces are allowed: argv exec handles them safely.
const PATH_FORBIDDEN: &[char] = &[
    ';', '&', '|', '$', '`', '\\', '"', '\'', '<', '>', '(', ')', '{', '}', '*', '?', '~', '#',
    '\0', '\n', '\r',
];

/// Validate a pcap path: no shell metacharacters, must canonicalize
/// to an existing regular file with a `.pcap`/`.pcapng`/`.cap`
/// extension, and — when `pcap_dir` is set — must resolve inside it.
/// Returns the canonical path.
pub fn validate_pcap_path(path: &str, pcap_dir: Option<&Path>) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("pcap path must not be empty".to_string());
    }
    for c in PATH_FORBIDDEN {
        if path.contains(*c) {
            return Err(format!("pcap path must not contain {c:?}"));
        }
    }
    let canon = Path::new(path)
        .canonicalize()
        .map_err(|e| format!("cannot access pcap file {path}: {e}"))?;
    if !canon.is_file() {
        return Err(format!("pcap path {path} is not a regular file"));
    }
    let ext = canon
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(ext.as_str(), "pcap" | "pcapng" | "cap") {
        return Err(format!(
            "pcap path {path} must end in .pcap, .pcapng, or .cap"
        ));
    }
    if let Some(dir) = pcap_dir {
        let canon_dir = dir.canonicalize().map_err(|e| {
            format!("{PCAP_DIR_ENV} {dir:?} is not accessible: {e}")
        })?;
        if !canon.starts_with(&canon_dir) {
            return Err(format!(
                "pcap path {path} is outside the allowed directory {canon_dir:?}"
            ));
        }
    }
    Ok(canon)
}

// ---------------------------------------------------------------------------
// tshark execution (direct exec, argv only — never a shell)
// ---------------------------------------------------------------------------

/// The captured output of one tshark run.
pub struct ExecOutcome {
    pub stdout: String,
    pub stderr: String,
}

/// Run tshark with the given argv, enforcing `timeout`. A non-zero
/// exit becomes an error carrying tshark's stderr (truncated); a
/// timeout kills the child and errors the same way.
pub async fn run_tshark(
    tshark: &Path,
    args: &[String],
    timeout: Duration,
) -> Result<ExecOutcome, String> {
    let run = async {
        TokioCommand::new(tshark)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .await
    };
    let output = tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| {
            format!(
                "tshark timed out after {}s (args: {})",
                timeout.as_secs(),
                truncate(&args.join(" "), 300)
            )
        })?
        .map_err(|e| format!("failed to run tshark {}: {e}", tshark.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        let detail = stderr.trim();
        let detail = if detail.is_empty() {
            "no error detail from tshark".to_string()
        } else {
            truncate(detail, 2000)
        };
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return Err(format!("tshark exited with status {code}: {detail}"));
    }
    Ok(ExecOutcome { stdout, stderr })
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

// ---------------------------------------------------------------------------
// tshark -T json packet parsing
// ---------------------------------------------------------------------------

/// First string of a tshark JSON field value, which is either a plain
/// string or a one-element array of strings.
fn first_str(v: &Value) -> Option<&str> {
    match v {
        Value::String(s) => Some(s.as_str()),
        Value::Array(a) => a.first().and_then(|x| x.as_str()),
        _ => None,
    }
}

fn layer<'a>(layers: &'a Value, name: &str) -> Option<&'a Value> {
    layers.get(name)
}

fn field<'a>(layer: Option<&'a Value>, key: &str) -> Option<&'a str> {
    layer.and_then(|l| first_str(&l[key]))
}

/// Parse `tshark -T json` stdout into normalized packet summaries.
/// Each summary carries only the fields an LLM needs to reason about
/// traffic — never raw packet bytes.
pub fn parse_packet_json(stdout: &str) -> Result<Vec<Value>, String> {
    let parsed: Value = serde_json::from_str(stdout)
        .map_err(|e| format!("tshark returned unparseable JSON: {e}"))?;
    let arr = parsed
        .as_array()
        .ok_or_else(|| "tshark JSON output was not an array".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for pkt in arr {
        let layers = pkt
            .get("_source")
            .and_then(|s| s.get("layers"))
            .cloned()
            .unwrap_or(Value::Null);
        let frame = layer(&layers, "frame");
        let col = layer(&layers, "_ws.col");
        let ip = layer(&layers, "ip").or_else(|| layer(&layers, "ipv6"));
        let eth = layer(&layers, "eth");
        let src = field(ip, "ip.src")
            .or_else(|| field(ip, "ipv6.src"))
            .or_else(|| field(eth, "eth.src"));
        let dst = field(ip, "ip.dst")
            .or_else(|| field(ip, "ipv6.dst"))
            .or_else(|| field(eth, "eth.dst"));
        out.push(serde_json::json!({
            "number": field(frame, "frame.number").and_then(|s| s.parse::<u64>().ok()),
            "time_epoch": field(frame, "frame.time_epoch").and_then(|s| s.parse::<f64>().ok()),
            "length": field(frame, "frame.len").and_then(|s| s.parse::<u64>().ok()),
            "protocol": field(col, "_ws.col.Protocol").or_else(|| field(frame, "frame.protocols")),
            "src": src,
            "dst": dst,
            "info": field(col, "_ws.col.Info"),
        }));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// tshark -D interface listing
// ---------------------------------------------------------------------------

/// Parse `tshark -D` output (`1. eth0` or `1. eth0 (Ethernet)`)
/// into `(name, description)` pairs, in listed order.
pub fn parse_tshark_d(stdout: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(rest) = line.split_once(". ") else {
            continue;
        };
        let rest = rest.1.trim();
        let (name, desc) = match rest.find(" (") {
            Some(idx) => {
                let name = rest[..idx].trim().to_string();
                let raw = &rest[idx + 2..];
                let desc = raw.strip_suffix(')').unwrap_or(raw).trim().to_string();
                (name, if desc.is_empty() { None } else { Some(desc) })
            }
            None => (rest.to_string(), None),
        };
        if name.is_empty() {
            continue;
        }
        out.push((name, desc));
    }
    out
}

/// Parse `tshark -L` output into the listed data-link type names.
pub fn parse_tshark_l(stdout: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Data link types") {
            continue;
        }
        // Lines look like "LINKTYPE_ETHERNET" or "DLT_EN10MB (Ethernet)";
        // keep the first token.
        let first = line.split_whitespace().next().unwrap_or("");
        if !first.is_empty() {
            out.push(first.to_string());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// OS interface details (Linux /sys/class/net, plus `ip -j address`)
// ---------------------------------------------------------------------------

fn read_sysfs_string(iface: &str, file: &str) -> Option<String> {
    // `iface` is already validated (no `/`), so this path cannot escape
    // /sys/class/net.
    let path = Path::new("/sys/class/net").join(iface).join(file);
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// ARPHRD numeric type (from /sys/class/net/<iface>/type) to a label.
/// The raw number is always reported alongside; the label is a nicety.
fn arphrd_label(n: u32) -> &'static str {
    match n {
        1 => "Ethernet",
        6 => "Token Ring",
        512 => "PPP",
        768 => "IP-over-IP tunnel",
        769 => "IPv6-over-IPv6 tunnel",
        772 => "Loopback",
        778 => "IEEE 802.11",
        65534 => "None",
        _ => "Unknown",
    }
}

/// IP addresses for one interface via `ip -j address show dev <iface>`
/// (argv exec; the interface name is validated). Returns an empty vec
/// — with a note — when `ip` is not installed; a missing interface
/// simply yields no addresses.
async fn interface_addresses(iface: &str, notes: &mut Vec<String>) -> Vec<Value> {
    let Some(ip) = search_path("ip") else {
        notes.push("`ip` command not found — addresses omitted".to_string());
        return Vec::new();
    };
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        TokioCommand::new(&ip)
            .args(["-j", "address", "show", "dev", iface])
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await;
    let output = match out {
        Ok(Ok(o)) => o,
        _ => return Vec::new(),
    };
    if !output.status.success() {
        return Vec::new();
    }
    let parsed: Value = match serde_json::from_slice(&output.stdout) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut addrs = Vec::new();
    if let Some(list) = parsed.as_array().and_then(|a| a.first()) {
        if let Some(info) = list.get("addr_info").and_then(|v| v.as_array()) {
            for a in info {
                addrs.push(serde_json::json!({
                    "family": a.get("family").and_then(|v| v.as_str()),
                    "address": a.get("local").and_then(|v| v.as_str()),
                    "prefixlen": a.get("prefixlen").and_then(|v| v.as_u64()),
                    "scope": a.get("scope").and_then(|v| v.as_str()),
                }));
            }
        }
    }
    addrs
}

/// Data-link types for one interface via `tshark -L -i <iface>`.
/// May need capture privileges; on failure returns None and the
/// caller records a note instead of failing the whole listing.
async fn link_layer_types(tshark: &Path, iface: &str) -> Option<Vec<String>> {
    let args = vec![
        "-L".to_string(),
        "-i".to_string(),
        iface.to_string(),
    ];
    let out = run_tshark(tshark, &args, Duration::from_secs(10))
        .await
        .ok()?;
    let types = parse_tshark_l(&out.stdout);
    if types.is_empty() {
        None
    } else {
        Some(types)
    }
}

// ---------------------------------------------------------------------------
// The three tools
// ---------------------------------------------------------------------------

/// Live capture: `tshark -i <iface> -c <count> [-a duration:N]
/// [-Y <filter>] -T json -n`. Returns packet summaries, never raw
/// bytes. Live capture needs capture privileges (wireshark group or
/// root); a permission failure surfaces as a tool error.
pub async fn tool_capture(
    tshark: &Path,
    interface: &str,
    filter: &str,
    count: i64,
    duration_secs: i64,
) -> Result<Value, String> {
    validate_interface_name(interface)?;
    validate_display_filter(filter)?;
    let count = count.clamp(1, MAX_CAPTURE_COUNT);
    let duration_secs = duration_secs.clamp(0, MAX_CAPTURE_DURATION_SECS);
    let mut args: Vec<String> = vec![
        "-i".to_string(),
        interface.to_string(),
        "-c".to_string(),
        count.to_string(),
        "-T".to_string(),
        "json".to_string(),
        "-n".to_string(),
    ];
    if duration_secs > 0 {
        args.push("-a".to_string());
        args.push(format!("duration:{duration_secs}"));
    }
    if !filter.is_empty() {
        args.push("-Y".to_string());
        args.push(filter.to_string());
    }
    // Bound the wait: the capture itself plus time to flush/parse.
    let timeout = Duration::from_secs((duration_secs as u64).saturating_add(30).clamp(30, 330));
    let out = run_tshark(tshark, &args, timeout).await?;
    let packets = parse_packet_json(&out.stdout)?;
    Ok(serde_json::json!({
        "interface": interface,
        "filter": filter,
        "requested_count": count,
        "duration_secs": duration_secs,
        "captured": packets.len(),
        "packets": packets,
    }))
}

/// pcap analysis: `tshark -r <path> -c <limit> [-Y <filter>] -T json
/// -n`. Reading a capture file needs no privileges.
pub async fn tool_analyze_pcap(
    tshark: &Path,
    path: &str,
    filter: &str,
    limit: i64,
    pcap_dir: Option<&Path>,
) -> Result<Value, String> {
    let canon = validate_pcap_path(path, pcap_dir)?;
    validate_display_filter(filter)?;
    let limit = limit.clamp(1, MAX_PCAP_LIMIT);
    let mut args: Vec<String> = vec![
        "-r".to_string(),
        canon.to_string_lossy().into_owned(),
        "-c".to_string(),
        limit.to_string(),
        "-T".to_string(),
        "json".to_string(),
        "-n".to_string(),
    ];
    if !filter.is_empty() {
        args.push("-Y".to_string());
        args.push(filter.to_string());
    }
    let out = run_tshark(tshark, &args, Duration::from_secs(60)).await?;
    let packets = parse_packet_json(&out.stdout)?;
    Ok(serde_json::json!({
        "path": canon.to_string_lossy(),
        "filter": filter,
        "limit": limit,
        "count": packets.len(),
        "packets": packets,
    }))
}

/// Full interface listing: `tshark -D` for names/descriptions, then
/// per-interface OS details (MAC, MTU, operstate, speed, ARPHRD
/// type from /sys/class/net), IP addresses via `ip -j address`, and
/// data-link types via `tshark -L`. Anything unavailable is null
/// with a note — the listing never fails over one missing detail.
pub async fn tool_interfaces(tshark: &Path) -> Result<Value, String> {
    let out = run_tshark(tshark, &["-D".to_string()], Duration::from_secs(10)).await?;
    let listed = parse_tshark_d(&out.stdout);
    if listed.is_empty() {
        return Err("tshark -D returned no interfaces".to_string());
    }
    let mut notes: Vec<String> = Vec::new();
    let mut ifaces: Vec<Value> = Vec::new();
    for (name, description) in listed {
        if validate_interface_name(&name).is_err() {
            notes.push(format!("skipping interface with unexpected name {name:?}"));
            continue;
        }
        let mac = read_sysfs_string(&name, "address");
        let mtu = read_sysfs_string(&name, "mtu").and_then(|s| s.parse::<u64>().ok());
        let operstate = read_sysfs_string(&name, "operstate");
        let speed = read_sysfs_string(&name, "speed").and_then(|s| s.parse::<u64>().ok());
        let link_type_num =
            read_sysfs_string(&name, "type").and_then(|s| s.parse::<u32>().ok());
        let link_type = link_type_num.map(|n| {
            serde_json::json!({ "arphrd": n, "label": arphrd_label(n) })
        });
        let addresses = interface_addresses(&name, &mut notes).await;
        let link_layer_types = match link_layer_types(tshark, &name).await {
            Some(t) => serde_json::json!(t),
            None => {
                notes.push(format!(
                    "could not list data-link types for {name} (needs capture privileges?)"
                ));
                Value::Null
            }
        };
        ifaces.push(serde_json::json!({
            "name": name,
            "description": description,
            "mac": mac,
            "mtu": mtu,
            "operstate": operstate,
            "speed_mbps": speed,
            "link_type": link_type,
            "addresses": addresses,
            "link_layer_types": link_layer_types,
        }));
    }
    Ok(serde_json::json!({
        "interfaces": ifaces,
        "notes": notes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- interface names -------------------------------------------------

    #[test]
    fn interface_names_accepted() {
        for name in [
            "eth0", "enp0s3", "lo", "any", "wlan0", "eth0@if2", "br-abc123", "bond0.100",
            "enx001122334455",
        ] {
            assert!(validate_interface_name(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn interface_names_rejected() {
        for name in [
            "",
            "-i",
            "--help",
            "eth0;id",
            "eth0|cat",
            "eth0 && id",
            "$(id)",
            "`id`",
            "eth 0",
            "eth0\n",
            "eth0/foo",
            "eth0$HOME",
            "..",
            ".",
            "eth0>out",
            "a".repeat(65).as_str(),
        ] {
            assert!(
                validate_interface_name(name).is_err(),
                "{name:?} should be rejected"
            );
        }
    }

    // -- display filters -------------------------------------------------

    #[test]
    fn display_filters_accepted() {
        for f in [
            "",
            "http",
            "tcp.port == 80",
            "ip.addr == 10.0.0.1 and tcp",
            "dns.flags.response == 1",
        ] {
            assert!(validate_display_filter(f).is_ok(), "{f:?} should be valid");
        }
    }

    #[test]
    fn display_filters_rejected() {
        assert!(validate_display_filter("http\nrm").is_err());
        assert!(validate_display_filter("http\0").is_err());
        assert!(validate_display_filter(&"x".repeat(MAX_FILTER_LEN + 1)).is_err());
    }

    // -- pcap paths ------------------------------------------------------

    fn write_test_pcap(dir: &str, name: &str) -> PathBuf {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, b"\xd4\xc3\xb2\xa1").unwrap();
        p
    }

    #[test]
    fn pcap_path_accepts_real_file() {
        let p = write_test_pcap("target/test-data", "sample.pcap");
        let got = validate_pcap_path(p.to_str().unwrap(), None).unwrap();
        assert!(got.ends_with("sample.pcap"));
        let p2 = write_test_pcap("target/test-data", "sample2.PCAPNG");
        assert!(validate_pcap_path(p2.to_str().unwrap(), None).is_ok());
    }

    #[test]
    fn pcap_path_rejects_bad_extension_and_missing() {
        let p = write_test_pcap("target/test-data", "notes.txt");
        assert!(validate_pcap_path(p.to_str().unwrap(), None).is_err());
        assert!(validate_pcap_path("target/test-data/nope.pcap", None).is_err());
        assert!(validate_pcap_path("", None).is_err());
    }

    #[test]
    fn pcap_path_rejects_metacharacters() {
        for bad in [
            "target/test-data/a;rm.pcap",
            "target/test-data/a|cat.pcap",
            "target/test-data/$(id).pcap",
            "target/test-data/a`id`.pcap",
        ] {
            assert!(validate_pcap_path(bad, None).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn pcap_path_scope_confines_to_dir() {
        let inside = write_test_pcap("target/test-data/allowed", "in.pcap");
        let outside = write_test_pcap("target/test-data", "out.pcap");
        let scope = Path::new("target/test-data/allowed");
        assert!(validate_pcap_path(inside.to_str().unwrap(), Some(scope)).is_ok());
        assert!(validate_pcap_path(outside.to_str().unwrap(), Some(scope)).is_err());
    }

    // -- tshark resolution ----------------------------------------------

    #[test]
    fn resolve_tshark_bogus_override_names_tshark() {
        let err = resolve_tshark(Some(Path::new("/nonexistent/tshark"))).unwrap_err();
        assert!(err.contains("tshark"), "error names tshark: {err}");
    }

    // -- parsers ----------------------------------------------------------

    #[test]
    fn parse_tshark_d_variants() {
        let out = "1. eth0\n2. any\n3. lo (Loopback)\n4. enp0s3 (Ethernet interface)\n";
        let got = parse_tshark_d(out);
        assert_eq!(got.len(), 4);
        assert_eq!(got[0], ("eth0".to_string(), None));
        assert_eq!(got[1], ("any".to_string(), None));
        assert_eq!(got[2], ("lo".to_string(), Some("Loopback".to_string())));
        assert_eq!(
            got[3],
            ("enp0s3".to_string(), Some("Ethernet interface".to_string()))
        );
    }

    #[test]
    fn parse_packet_json_normalizes_fields() {
        let stdout = r#"[{"_index":"packets-1","_type":"pcap_file","_score":null,"_source":{"layers":{"frame":{"frame.number":["1"],"frame.time_epoch":["1700000000.123456"],"frame.len":["74"],"frame.protocols":["eth:ethertype:ip:tcp"]},"eth":{"eth.src":["aa:bb:cc:dd:ee:ff"],"eth.dst":["11:22:33:44:55:66"]},"ip":{"ip.src":["10.0.0.1"],"ip.dst":["10.0.0.2"]},"_ws.col":{"_ws.col.Protocol":["TCP"],"_ws.col.Info":["443 → 12345 [SYN]"]}}}}]"#;
        let pkts = parse_packet_json(stdout).unwrap();
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0]["number"], 1);
        assert_eq!(pkts[0]["src"], "10.0.0.1");
        assert_eq!(pkts[0]["dst"], "10.0.0.2");
        assert_eq!(pkts[0]["protocol"], "TCP");
        assert_eq!(pkts[0]["length"], 74);
        assert_eq!(pkts[0]["info"], "443 → 12345 [SYN]");
    }

    #[test]
    fn parse_packet_json_empty_array() {
        assert_eq!(parse_packet_json("[]").unwrap().len(), 0);
        assert!(parse_packet_json("not json").is_err());
    }
}

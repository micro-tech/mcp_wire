# mcp-wire

A standalone MCP server (stdio) that exposes Wireshark/tshark to any
LLM: live packet capture, pcap file analysis, and full interface
details. Consumer-agnostic — Helix is the first client, but nothing
here is Helix-specific. Follows the chat-mcp 0.1.0 pattern (Rust,
JSON-RPC 2.0 over stdio).

## Prerequisites

- Rust (stable, 1.75+)
- **tshark** (part of Wireshark) on the machine that runs the server.
  The server starts without it, but every tool then returns a clear
  error naming tshark instead of working. Install from
  <https://www.wireshark.org/download.html> or your package manager
  (`apt install tshark`, `brew install wireshark`, …).

## Build

```text
cargo build --release
```

The binary is `target/release/mcp-wire`.

## Run

The server speaks MCP (JSON-RPC 2.0, newline-delimited) on stdio.
Stdout is the protocol; all logging goes to stderr.

```text
mcp-wire [--tshark <path>]
```

tshark is resolved as: `--tshark` flag, then the `TSHARK_PATH`
environment variable, then PATH.

### Wiring it into Helix

```toml
[mcp.servers]
wire = { command = "/path/to/mcp-wire" }
```

Any MCP client can spawn it the same way.

## Tools

### `capture`

Live capture on an interface. Returns packet summaries — number,
time, src, dst, protocol, length, info — never raw packet bytes.

```json
{"name": "capture", "arguments": {
  "interface": "eth0",
  "filter": "tcp.port == 443",
  "count": 20,
  "duration_secs": 0
}}
```

- `interface` (required): e.g. `eth0`, `enp0s3`, `lo`, `any`.
- `filter` (optional): Wireshark display filter (`-Y`). Empty means
  no filter.
- `count` (optional): stop after this many packets. Default 10,
  clamped 1..=1000.
- `duration_secs` (optional): stop after this many seconds. 0 means
  no time cap, clamped 0..=300. When both are set, whichever hits
  first stops the capture.

### `analyze_pcap`

Read a pcap/pcapng file and return packet summaries in the same
shape as `capture`. Reading a file needs no capture privileges.

```json
{"name": "analyze_pcap", "arguments": {
  "path": "/home/cobble/captures/dns-issue.pcap",
  "filter": "dns",
  "limit": 50
}}
```

- `path` (required): must end in `.pcap`, `.pcapng`, or `.cap`.
- `filter` (optional): display filter.
- `limit` (optional): max packets to return. Default 50, clamped
  1..=500.

Set `MCP_WIRE_PCAP_DIR` to confine `analyze_pcap` to one directory
tree; paths outside it are rejected.

### `interfaces`

Full detail on every capture interface — name, description, MAC,
MTU, operstate, speed, link-layer type, IP addresses, and supported
data-link types. Anything unavailable on the host is `null` with a
note explaining why.

```json
{"name": "interfaces", "arguments": {}}
```

## Privileges

Live capture needs capture privileges: the user running `mcp-wire`
must be in the `wireshark` group (or equivalent) or root. The
server never escalates — if tshark cannot open the interface, the
tool returns tshark's permission error. `analyze_pcap` and most of
`interfaces` need no privileges (listing data-link types may).

## Security

- tshark is invoked by direct exec with an argv array. There is no
  shell anywhere in this codebase.
- Interface names are whitelisted (`[A-Za-z0-9_.\-@]`, max 64 chars,
  never starting with `-`), so a value can never be mistaken for a
  tshark flag or smuggle a metacharacter.
- Display filters are length-capped and checked for NUL/newline,
  then passed as a single argv element.
- pcap paths are canonicalized, extension-checked, and (when
  `MCP_WIRE_PCAP_DIR` is set) confined under that directory.
- No auth in v1: the transport is stdio and local-only. Do not
  expose this server over a network socket without adding auth.

## Environment

| Variable | Purpose |
| --- | --- |
| `TSHARK_PATH` | Override the tshark binary path |
| `MCP_WIRE_PCAP_DIR` | Confine `analyze_pcap` to this directory tree |

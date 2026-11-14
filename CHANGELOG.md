# Changelog

## 0.1.0 — 2026-11-13

Initial scaffold.

- Stdio MCP server (JSON-RPC 2.0, MCP `2024-11-05`), following the
  chat-mcp 0.1.0 pattern: `initialize`, `ping`, `tools/list`,
  `tools/call`, notifications get no response.
- Three tools, all wrapping tshark by direct argv exec (no shell):
  - `capture` — live capture with display filter, packet-count and/or
    duration cap; returns packet summaries, never raw bytes.
  - `analyze_pcap` — read a pcap/pcapng file with display filter
    and packet limit; canonicalized paths, extension whitelist,
    optional `MCP_WIRE_PCAP_DIR` scope.
  - `interfaces` — full interface detail: name, description, MAC,
    MTU, operstate, speed, link-layer type, IP addresses, supported
    data-link types; unavailable details are null with a note.
- Security: interface-name whitelist, filter/path validation,
  tshark-missing returns a clear error naming tshark (server never
  crashes over a missing dependency). No auth in v1 (stdio, local
  only) — documented in the README.
- Tests: unit tests for validation, parsers, and the tshark-missing
  path; stub-tshark tests for the happy path; e2e tests driving the
  real binary over stdio.

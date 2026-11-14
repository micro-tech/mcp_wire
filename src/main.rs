//! mcp-wire binary: spawnable MCP server (stdio) for Wireshark.
//!
//! Any MCP client (Helix, grok-cli, Claude Desktop, …) spawns this
//! binary and talks JSON-RPC over stdio. Usage:
//!
//! ```text
//! mcp-wire [--tshark <path>]
//! ```
//!
//! The tshark binary is resolved as: `--tshark` flag, then the
//! `TSHARK_PATH` environment variable, then PATH. When tshark is
//! missing the server still starts and the tools return a clear error
//! naming tshark — it never crashes over a missing dependency. All
//! logging goes to stderr; stdout is the MCP protocol.

use mcp_wire::{resolve_tshark, run_stdio, ServerConfig};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: mcp-wire [--tshark <path>]

Options:
  --tshark <path>  Path to the tshark binary (overrides TSHARK_PATH and PATH)
  --help, -h       Show this help

The server speaks MCP (JSON-RPC 2.0) on stdio. Live capture needs
capture privileges (member of the wireshark group or root); the
server never escalates — a permission failure is a tool error.";

fn main() -> ExitCode {
    let mut tshark_path: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--tshark" => match args.next() {
                Some(p) => tshark_path = Some(PathBuf::from(p)),
                None => {
                    eprintln!("mcp-wire: --tshark needs a path\n{USAGE}");
                    return ExitCode::FAILURE;
                }
            },
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("mcp-wire: unknown argument {other:?}\n{USAGE}");
                return ExitCode::FAILURE;
            }
        }
    }

    match resolve_tshark(tshark_path.as_deref()) {
        Ok(p) => eprintln!("mcp-wire: serving on stdio, tshark {}", p.display()),
        Err(e) => eprintln!("mcp-wire: serving on stdio (warning: {e})"),
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mcp-wire: cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run_stdio(ServerConfig::new(tshark_path)));
    ExitCode::SUCCESS
}

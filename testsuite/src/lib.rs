#![allow(
    clippy::print_stderr,
    reason = "test infrastructure can intentionally use eprintln for debug output"
)]
#![allow(clippy::unwrap_used, reason = "test infrastructure can panic on errors")]

pub mod cli;
pub mod dgw_config;
pub mod honeypot_control_plane;
pub mod honeypot_docs;
pub mod honeypot_frontend;
pub mod honeypot_manual_ironrdp_rdpgfx;
pub mod honeypot_manual_lab;
pub mod honeypot_release;
pub mod honeypot_tiers;
pub mod mcp_client;
pub mod mcp_server;
pub mod ports;

#![allow(clippy::unwrap_used, reason = "test code can panic on errors")]
#![allow(clippy::print_stdout, reason = "test code uses print for diagnostics")]
#![allow(clippy::print_stderr, reason = "test code uses print for diagnostics")]

mod cli;
mod honeypot_control_plane;
mod honeypot_docs;
mod honeypot_frontend;
mod honeypot_release;
mod honeypot_tiers;
mod honeypot_visibility;
mod mcp_proxy;
mod sysevent;

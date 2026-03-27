use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;

use anyhow::Context as _;
use typed_builder::TypedBuilder;

static HONEYPOT_FRONTEND_BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path("../honeypot/frontend/Cargo.toml")
        .bin("honeypot-frontend")
        .current_release()
        .current_target()
        .run()
        .expect("build honeypot frontend")
        .path()
        .to_path_buf()
});

#[derive(Debug, Clone, TypedBuilder)]
pub struct HoneypotFrontendTestConfig {
    #[builder(setter(into))]
    pub bind_addr: String,
    #[builder(setter(into))]
    pub proxy_base_url: String,
    #[builder(default = "/jet/honeypot/bootstrap".to_owned(), setter(into))]
    pub proxy_bootstrap_path: String,
    #[builder(default = "/jet/honeypot/events".to_owned(), setter(into))]
    pub proxy_events_path: String,
    #[builder(default = "/jet/honeypot/session/{session_id}/stream-token".to_owned(), setter(into))]
    pub proxy_stream_token_path_template: String,
    #[builder(default = "/jet/session/{session_id}/propose".to_owned(), setter(into))]
    pub proxy_propose_path_template: String,
    #[builder(default = "/jet/session/{session_id}/terminate".to_owned(), setter(into))]
    pub proxy_terminate_path_template: String,
    #[builder(default = "/jet/session/{session_id}/quarantine".to_owned(), setter(into))]
    pub proxy_quarantine_path_template: String,
    #[builder(default = "/jet/session/system/terminate".to_owned(), setter(into))]
    pub proxy_system_terminate_path: String,
    #[builder(default, setter(into))]
    pub proxy_bearer_token: Option<String>,
    #[builder(default = true)]
    pub operator_token_validation_disabled: bool,
    #[builder(default, setter(into))]
    pub operator_verifier_public_key_pem: Option<String>,
    #[builder(default = "Observation Deck".to_owned(), setter(into))]
    pub title: String,
}

pub fn honeypot_frontend_assert_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(&*HONEYPOT_FRONTEND_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

pub fn honeypot_frontend_tokio_cmd() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&*HONEYPOT_FRONTEND_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd.kill_on_drop(true);
    cmd.stdout(Stdio::null());
    cmd
}

pub fn write_honeypot_frontend_config(path: &Path, config: &HoneypotFrontendTestConfig) -> anyhow::Result<()> {
    let mut document = format!(
        "[http]\n\
         bind_addr = \"{}\"\n\n\
         [proxy]\n\
         base_url = \"{}\"\n\
         bootstrap_path = \"{}\"\n\
         events_path = \"{}\"\n\
         stream_token_path_template = \"{}\"\n\n\
         propose_path_template = \"{}\"\n\
         terminate_path_template = \"{}\"\n\
         quarantine_path_template = \"{}\"\n\
         system_terminate_path = \"{}\"\n\n\
         [ui]\n\
         title = \"{}\"\n",
        config.bind_addr,
        config.proxy_base_url,
        config.proxy_bootstrap_path,
        config.proxy_events_path,
        config.proxy_stream_token_path_template,
        config.proxy_propose_path_template,
        config.proxy_terminate_path_template,
        config.proxy_quarantine_path_template,
        config.proxy_system_terminate_path,
        config.title,
    );

    document.push_str("\n[auth]\n");

    if let Some(token) = &config.proxy_bearer_token {
        document.push_str(&format!("proxy_bearer_token = \"{}\"\n", token));
    }

    document.push_str(&format!(
        "operator_token_validation_disabled = {}\n",
        config.operator_token_validation_disabled
    ));

    if let Some(pem) = &config.operator_verifier_public_key_pem {
        document.push_str(&format!("operator_verifier_public_key_pem = '''\n{}\n'''\n", pem));
    }

    std::fs::write(path, document).with_context(|| format!("write frontend config at {}", path.display()))
}

pub async fn read_http_response(port: u16, path: &str) -> anyhow::Result<(String, String, Vec<u8>)> {
    send_http_request(port, "GET", path, None, &[]).await
}

pub async fn send_http_request(
    port: u16,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> anyhow::Result<(String, String, Vec<u8>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("connect to honeypot frontend on port {port}"))?;

    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    if let Some(content_type) = content_type {
        request.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    stream
        .write_all(request.as_bytes())
        .await
        .with_context(|| format!("send {method} frontend request to {path}"))?;
    if !body.is_empty() {
        stream
            .write_all(body)
            .await
            .with_context(|| format!("send {method} frontend request body to {path}"))?;
    }

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .with_context(|| format!("read {method} frontend response from {path}"))?;

    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("split frontend response headers and body")?;
    let headers = std::str::from_utf8(&response[..header_end]).context("decode frontend headers")?;
    let status_line = headers
        .lines()
        .next()
        .context("extract frontend status line")?
        .to_owned();

    Ok((status_line, headers.to_owned(), response[(header_end + 4)..].to_vec()))
}

pub fn find_unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind localhost ephemeral port")
        .local_addr()
        .expect("read ephemeral port")
        .port()
}

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;

use anyhow::Context as _;
use honeypot_contracts::control_plane::HealthResponse;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use typed_builder::TypedBuilder;

static HONEYPOT_CONTROL_PLANE_BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path("../honeypot/control-plane/Cargo.toml")
        .bin("honeypot-control-plane")
        .current_release()
        .current_target()
        .run()
        .expect("build honeypot control-plane")
        .path()
        .to_path_buf()
});

#[derive(Debug, Clone, TypedBuilder)]
pub struct HoneypotControlPlaneTestConfig {
    #[builder(setter(into))]
    pub bind_addr: String,
    #[builder(setter(into))]
    pub data_dir: PathBuf,
    #[builder(setter(into))]
    pub image_store: PathBuf,
    #[builder(setter(into))]
    pub manifest_dir: PathBuf,
    #[builder(setter(into))]
    pub lease_store: PathBuf,
    #[builder(setter(into))]
    pub quarantine_store: PathBuf,
    #[builder(setter(into))]
    pub qmp_dir: PathBuf,
    #[builder(default, setter(into, strip_option))]
    pub qga_dir: Option<PathBuf>,
    #[builder(setter(into))]
    pub secret_dir: PathBuf,
    #[builder(setter(into))]
    pub kvm_path: PathBuf,
    #[builder(default = false)]
    pub enable_guest_agent: bool,
}

pub fn honeypot_control_plane_assert_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(&*HONEYPOT_CONTROL_PLANE_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

pub fn honeypot_control_plane_tokio_cmd() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&*HONEYPOT_CONTROL_PLANE_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd.kill_on_drop(true);
    cmd.stdout(Stdio::null());
    cmd
}

pub fn write_honeypot_control_plane_config(path: &Path, config: &HoneypotControlPlaneTestConfig) -> anyhow::Result<()> {
    let mut document = format!(
        "[http]\n\
         bind_addr = \"{}\"\n\n\
         [runtime]\n\
         enable_guest_agent = {}\n\n\
         [paths]\n\
         data_dir = \"{}\"\n\
         image_store = \"{}\"\n\
         manifest_dir = \"{}\"\n\
         lease_store = \"{}\"\n\
         quarantine_store = \"{}\"\n\
         qmp_dir = \"{}\"\n\
         secret_dir = \"{}\"\n\
         kvm_path = \"{}\"\n",
        config.bind_addr,
        config.enable_guest_agent,
        config.data_dir.display(),
        config.image_store.display(),
        config.manifest_dir.display(),
        config.lease_store.display(),
        config.quarantine_store.display(),
        config.qmp_dir.display(),
        config.secret_dir.display(),
        config.kvm_path.display(),
    );

    if let Some(qga_dir) = &config.qga_dir {
        document.push_str(&format!("qga_dir = \"{}\"\n", qga_dir.display()));
    }

    std::fs::write(path, document).with_context(|| format!("write control-plane config at {}", path.display()))
}

pub async fn read_health_response(port: u16) -> anyhow::Result<HealthResponse> {
    let (_, response) = get_json_response(port, "/api/v1/health").await?;
    Ok(response)
}

pub async fn get_json_response<Response>(port: u16, path: &str) -> anyhow::Result<(String, Response)>
where
    Response: DeserializeOwned,
{
    let (status_line, body) = send_http_request(port, "GET", path, None).await?;
    let response = serde_json::from_slice(&body).context("parse json response body")?;
    Ok((status_line, response))
}

pub async fn post_json_response<Request, Response>(
    port: u16,
    path: &str,
    request: &Request,
) -> anyhow::Result<(String, Response)>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    let body = serde_json::to_vec(request).context("serialize json request body")?;
    let (status_line, body) = send_http_request(port, "POST", path, Some(&body)).await?;
    let response = serde_json::from_slice(&body).context("parse json response body")?;
    Ok((status_line, response))
}

pub async fn send_http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> anyhow::Result<(String, Vec<u8>)> {
    let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("connect to honeypot control-plane endpoint on port {port}"))?;

    let request = match body {
        Some(body) => format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ),
        None => format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    };

    stream
        .write_all(request.as_bytes())
        .await
        .context("write control-plane request headers")?;

    if let Some(body) = body {
        stream
            .write_all(body)
            .await
            .context("write control-plane request body")?;
    }

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .context("read control-plane response")?;

    let response = String::from_utf8(response).context("decode control-plane response as utf-8")?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .context("split control-plane response headers and body")?;
    let status_line = headers
        .lines()
        .next()
        .context("read control-plane status line")?
        .to_owned();

    Ok((status_line, body.as_bytes().to_vec()))
}

pub fn find_unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind localhost ephemeral port")
        .local_addr()
        .expect("read ephemeral port")
        .port()
}

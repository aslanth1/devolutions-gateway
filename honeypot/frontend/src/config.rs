use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;

use anyhow::Context as _;
use serde::Deserialize;
use url::Url;

pub const DEFAULT_FRONTEND_CONFIG_PATH: &str = "/etc/honeypot/frontend/config.toml";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FrontendConfig {
    pub http: HttpConfig,
    pub proxy: ProxyConfig,
    pub auth: AuthConfig,
    pub ui: UiConfig,
}

impl FrontendConfig {
    pub fn load_from_path(path: &Path) -> anyhow::Result<Self> {
        let data =
            std::fs::read_to_string(path).with_context(|| format!("read frontend config at {}", path.display()))?;

        toml::from_str(&data).with_context(|| format!("parse frontend config at {}", path.display()))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    pub bind_addr: SocketAddr,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8086)),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub base_url: Url,
    pub bootstrap_path: String,
    pub events_path: String,
    pub stream_token_path_template: String,
    pub request_timeout_secs: u64,
    pub connect_timeout_secs: u64,
}

impl ProxyConfig {
    pub fn bootstrap_url(&self) -> anyhow::Result<Url> {
        self.url_for_path(&self.bootstrap_path)
    }

    pub fn events_url(&self, cursor: &str) -> anyhow::Result<Url> {
        let mut url = self.url_for_path(&self.events_path)?;
        url.query_pairs_mut().append_pair("cursor", cursor);
        Ok(url)
    }

    pub fn stream_token_url(&self, session_id: &str) -> anyhow::Result<Url> {
        let path = self.stream_token_path_template.replace("{session_id}", session_id);

        self.url_for_path(&path)
    }

    fn url_for_path(&self, path: &str) -> anyhow::Result<Url> {
        let trimmed = path.trim_start_matches('/');
        self.base_url
            .join(trimmed)
            .with_context(|| format!("join proxy base url {} with path {path}", self.base_url))
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            base_url: Url::parse("http://127.0.0.1:7171/").expect("valid default proxy url"),
            bootstrap_path: "/jet/honeypot/bootstrap".to_owned(),
            events_path: "/jet/honeypot/events".to_owned(),
            stream_token_path_template: "/jet/honeypot/session/{session_id}/stream-token".to_owned(),
            request_timeout_secs: 10,
            connect_timeout_secs: 5,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub proxy_bearer_token: Option<String>,
    pub operator_token_validation_disabled: bool,
    pub operator_verifier_public_key_pem: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    pub title: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            title: "Observation Deck".to_owned(),
        }
    }
}

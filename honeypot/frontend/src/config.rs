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
    pub clipboard_path_template: String,
    pub keyboard_path_template: String,
    pub propose_path_template: String,
    pub vote_path_template: String,
    pub terminate_path_template: String,
    pub quarantine_path_template: String,
    pub system_terminate_path: String,
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

    pub fn clipboard_url(&self, session_id: &str) -> anyhow::Result<Url> {
        let path = self.clipboard_path_template.replace("{session_id}", session_id);

        self.url_for_path(&path)
    }

    pub fn keyboard_url(&self, session_id: &str) -> anyhow::Result<Url> {
        let path = self.keyboard_path_template.replace("{session_id}", session_id);

        self.url_for_path(&path)
    }

    pub fn propose_url(&self, session_id: &str) -> anyhow::Result<Url> {
        let path = self.propose_path_template.replace("{session_id}", session_id);

        self.url_for_path(&path)
    }

    pub fn vote_url(&self, session_id: &str) -> anyhow::Result<Url> {
        let path = self.vote_path_template.replace("{session_id}", session_id);

        self.url_for_path(&path)
    }

    pub fn resolve_stream_url(&self, endpoint: &str) -> anyhow::Result<Url> {
        if let Ok(url) = Url::parse(endpoint) {
            return Ok(url);
        }

        self.url_for_path(endpoint)
    }

    pub fn terminate_url(&self, session_id: &str) -> anyhow::Result<Url> {
        let path = self.terminate_path_template.replace("{session_id}", session_id);

        self.url_for_path(&path)
    }

    pub fn quarantine_url(&self, session_id: &str) -> anyhow::Result<Url> {
        let path = self.quarantine_path_template.replace("{session_id}", session_id);

        self.url_for_path(&path)
    }

    pub fn system_terminate_url(&self) -> anyhow::Result<Url> {
        self.url_for_path(&self.system_terminate_path)
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
            clipboard_path_template: "/jet/session/{session_id}/clipboard".to_owned(),
            keyboard_path_template: "/jet/session/{session_id}/keyboard".to_owned(),
            propose_path_template: "/jet/session/{session_id}/propose".to_owned(),
            vote_path_template: "/jet/session/{session_id}/vote".to_owned(),
            terminate_path_template: "/jet/session/{session_id}/terminate".to_owned(),
            quarantine_path_template: "/jet/session/{session_id}/quarantine".to_owned(),
            system_terminate_path: "/jet/session/system/terminate".to_owned(),
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

#[cfg(test)]
mod tests {
    use super::FrontendConfig;

    #[test]
    fn frontend_config_rejects_invalid_bind_addr() {
        let error = toml::from_str::<FrontendConfig>(
            r#"
[http]
bind_addr = "not-a-socket"
"#,
        )
        .expect_err("invalid bind_addr must be rejected");
        let rendered = error.to_string();

        assert!(
            rendered.contains("bind_addr") || rendered.contains("socket"),
            "{rendered}"
        );
    }

    #[test]
    fn frontend_config_rejects_invalid_proxy_base_url() {
        let error = toml::from_str::<FrontendConfig>(
            r#"
[proxy]
base_url = "frontend.internal without scheme"
"#,
        )
        .expect_err("invalid proxy base_url must be rejected");
        let rendered = error.to_string();

        assert!(
            rendered.contains("base_url") || rendered.contains("relative URL") || rendered.contains("url"),
            "{rendered}"
        );
    }
}

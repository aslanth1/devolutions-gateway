use core::fmt;
use std::path::Path;

use anyhow::Context as _;
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use typed_builder::TypedBuilder;

pub struct VerbosityProfile(&'static str);

impl VerbosityProfile {
    pub const DEFAULT: Self = Self("Default");
    pub const DEBUG: Self = Self("Debug");
    pub const TLS: Self = Self("Tls");
    pub const ALL: Self = Self("All");
    pub const QUIET: Self = Self("Quiet");
}

impl fmt::Display for VerbosityProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Configuration for the AI Gateway feature in tests.
#[derive(Clone, Default, TypedBuilder)]
pub struct AiGatewayConfig {
    /// Whether the AI gateway is enabled.
    #[builder(default = false)]
    pub enabled: bool,
    /// Optional API key for gateway-level authentication.
    #[builder(default, setter(into))]
    pub gateway_api_key: Option<String>,
    /// Custom endpoint for the OpenAI provider (for mock server).
    #[builder(default, setter(into))]
    pub openai_endpoint: Option<String>,
    /// API key for OpenAI provider.
    #[builder(default, setter(into))]
    pub openai_api_key: Option<String>,
}

/// Configuration for the honeypot feature in tests.
#[derive(Clone, Default, TypedBuilder)]
pub struct HoneypotConfig {
    /// Whether honeypot mode is enabled.
    #[builder(default = false)]
    pub enabled: bool,
    /// Optional internal control-plane endpoint.
    #[builder(default, setter(into))]
    pub control_plane_endpoint: Option<String>,
    /// Optional control-plane request timeout in seconds.
    #[builder(default, setter(strip_option))]
    pub control_plane_request_timeout_secs: Option<u64>,
    /// Optional control-plane connect timeout in seconds.
    #[builder(default, setter(strip_option))]
    pub control_plane_connect_timeout_secs: Option<u64>,
    /// Optional proxy-to-control-plane bearer token.
    #[builder(default, setter(into))]
    pub control_plane_service_bearer_token: Option<String>,
    /// Optional proxy-to-control-plane bearer token file path.
    #[builder(default, setter(into))]
    pub control_plane_service_bearer_token_file: Option<String>,
    /// Optional stream source kind.
    #[builder(default, setter(into))]
    pub stream_source_kind: Option<String>,
    /// Optional browser transport.
    #[builder(default, setter(into))]
    pub stream_browser_transport: Option<String>,
    /// Optional stream token TTL in seconds.
    #[builder(default, setter(strip_option))]
    pub stream_token_ttl_secs: Option<u64>,
    /// Optional operator authentication mode.
    #[builder(default, setter(into))]
    pub operator_auth_mode: Option<String>,
    /// Optional operator app-token maximum lifetime in seconds.
    #[builder(default, setter(strip_option))]
    pub operator_app_token_maximum_lifetime_secs: Option<u64>,
    /// Optional operator access-token maximum lifetime in seconds.
    #[builder(default, setter(strip_option))]
    pub operator_access_token_maximum_lifetime_secs: Option<u64>,
    /// Optional session-kill enablement.
    #[builder(default, setter(strip_option))]
    pub enable_session_kill: Option<bool>,
    /// Optional system-kill enablement.
    #[builder(default, setter(strip_option))]
    pub enable_system_kill: Option<bool>,
    /// Optional intake halt on system kill.
    #[builder(default, setter(strip_option))]
    pub halt_new_sessions_on_system_kill: Option<bool>,
    /// Optional public frontend URL.
    #[builder(default, setter(into))]
    pub frontend_public_url: Option<String>,
    /// Optional frontend bootstrap path.
    #[builder(default, setter(into))]
    pub frontend_bootstrap_path: Option<String>,
    /// Optional frontend events path.
    #[builder(default, setter(into))]
    pub frontend_events_path: Option<String>,
}

#[derive(TypedBuilder)]
pub struct DgwConfig {
    #[builder(default, setter(into))]
    tcp_port: Option<u16>,
    #[builder(default, setter(into))]
    http_port: Option<u16>,
    #[builder(default = false)]
    disable_token_validation: bool,
    #[builder(default = VerbosityProfile::DEFAULT)]
    verbosity_profile: VerbosityProfile,
    /// AI gateway configuration (requires enable_unstable: true to work).
    #[builder(default, setter(into))]
    ai_gateway: Option<AiGatewayConfig>,
    /// Honeypot configuration.
    #[builder(default, setter(into))]
    honeypot: Option<HoneypotConfig>,
    /// Enable unstable features (required for AI gateway).
    #[builder(default = false)]
    enable_unstable: bool,
}

fn find_unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl DgwConfig {
    pub fn init(self) -> anyhow::Result<DgwConfigHandle> {
        DgwConfigHandle::init(self)
    }
}

pub struct DgwConfigHandle {
    tempdir: TempDir,
    tcp_port: u16,
    http_port: u16,
}

impl DgwConfigHandle {
    pub fn init(config: DgwConfig) -> anyhow::Result<Self> {
        let DgwConfig {
            tcp_port,
            http_port,
            disable_token_validation,
            verbosity_profile,
            ai_gateway,
            honeypot,
            enable_unstable,
        } = config;

        let tempdir = tempfile::tempdir().context("create tempdir")?;
        let config_path = tempdir.path().join("gateway.json");

        let tcp_port = tcp_port.unwrap_or_else(find_unused_port);
        let http_port = http_port.unwrap_or_else(find_unused_port);

        let mut config = Map::new();
        config.insert(
            "ProvisionerPublicKeyData".to_owned(),
            json!({
                "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HgjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
            }),
        );
        config.insert(
            "Listeners".to_owned(),
            json!([
                {
                    "InternalUrl": format!("tcp://127.0.0.1:{tcp_port}"),
                    "ExternalUrl": format!("tcp://127.0.0.1:{tcp_port}")
                },
                {
                    "InternalUrl": format!("http://127.0.0.1:{http_port}"),
                    "ExternalUrl": format!("http://127.0.0.1:{http_port}")
                }
            ]),
        );
        config.insert("VerbosityProfile".to_owned(), json!(verbosity_profile.to_string()));
        config.insert(
            "__debug__".to_owned(),
            json!({
                "disable_token_validation": disable_token_validation,
                "enable_unstable": enable_unstable
            }),
        );

        if let Some(ai_config) = ai_gateway {
            config.insert("AiGateway".to_owned(), build_ai_gateway_config_json(ai_config));
        }

        if let Some(honeypot_config) = honeypot {
            config.insert("Honeypot".to_owned(), build_honeypot_config_json(honeypot_config));
        }

        let config = serde_json::to_string_pretty(&Value::Object(config)).context("serialize gateway config")?;

        std::fs::write(&config_path, config).with_context(|| format!("write config into {}", config_path.display()))?;

        Ok(Self {
            tempdir,
            tcp_port,
            http_port,
        })
    }

    pub fn config_dir(&self) -> &Path {
        self.tempdir.path()
    }

    pub fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    pub fn http_port(&self) -> u16 {
        self.http_port
    }
}

fn build_ai_gateway_config_json(ai_config: AiGatewayConfig) -> Value {
    let mut gateway = Map::new();
    gateway.insert("Enabled".to_owned(), json!(ai_config.enabled));
    gateway.insert("RequestTimeoutSecs".to_owned(), json!(30));

    if let Some(gateway_api_key) = ai_config.gateway_api_key {
        gateway.insert("GatewayApiKey".to_owned(), json!(gateway_api_key));
    }

    let mut providers = Map::new();
    let mut openai = Map::new();

    if let Some(endpoint) = ai_config.openai_endpoint {
        openai.insert("Endpoint".to_owned(), json!(endpoint));
    }

    if let Some(api_key) = ai_config.openai_api_key {
        openai.insert("ApiKey".to_owned(), json!(api_key));
    }

    if !openai.is_empty() {
        providers.insert("Openai".to_owned(), Value::Object(openai));
    }

    if !providers.is_empty() {
        gateway.insert("Providers".to_owned(), Value::Object(providers));
    }

    Value::Object(gateway)
}

fn build_honeypot_config_json(honeypot_config: HoneypotConfig) -> Value {
    let mut honeypot = Map::new();
    honeypot.insert("Enabled".to_owned(), json!(honeypot_config.enabled));

    let mut control_plane = Map::new();
    if let Some(endpoint) = honeypot_config.control_plane_endpoint {
        control_plane.insert("Endpoint".to_owned(), json!(endpoint));
    }
    if let Some(request_timeout_secs) = honeypot_config.control_plane_request_timeout_secs {
        control_plane.insert("RequestTimeoutSecs".to_owned(), json!(request_timeout_secs));
    }
    if let Some(connect_timeout_secs) = honeypot_config.control_plane_connect_timeout_secs {
        control_plane.insert("ConnectTimeoutSecs".to_owned(), json!(connect_timeout_secs));
    }
    if let Some(service_bearer_token) = honeypot_config.control_plane_service_bearer_token {
        control_plane.insert("ServiceBearerToken".to_owned(), json!(service_bearer_token));
    }
    if let Some(service_bearer_token_file) = honeypot_config.control_plane_service_bearer_token_file {
        control_plane.insert("ServiceBearerTokenFile".to_owned(), json!(service_bearer_token_file));
    }
    if !control_plane.is_empty() {
        honeypot.insert("ControlPlane".to_owned(), Value::Object(control_plane));
    }

    let mut stream = Map::new();
    if let Some(source_kind) = honeypot_config.stream_source_kind {
        stream.insert("SourceKind".to_owned(), json!(source_kind));
    }
    if let Some(browser_transport) = honeypot_config.stream_browser_transport {
        stream.insert("BrowserTransport".to_owned(), json!(browser_transport));
    }
    if let Some(token_ttl_secs) = honeypot_config.stream_token_ttl_secs {
        stream.insert("TokenTtlSecs".to_owned(), json!(token_ttl_secs));
    }
    if !stream.is_empty() {
        honeypot.insert("Stream".to_owned(), Value::Object(stream));
    }

    let mut operator_auth = Map::new();
    if let Some(mode) = honeypot_config.operator_auth_mode {
        operator_auth.insert("Mode".to_owned(), json!(mode));
    }
    if let Some(app_token_maximum_lifetime_secs) = honeypot_config.operator_app_token_maximum_lifetime_secs {
        operator_auth.insert(
            "AppTokenMaximumLifetimeSecs".to_owned(),
            json!(app_token_maximum_lifetime_secs),
        );
    }
    if let Some(access_token_maximum_lifetime_secs) = honeypot_config.operator_access_token_maximum_lifetime_secs {
        operator_auth.insert(
            "AccessTokenMaximumLifetimeSecs".to_owned(),
            json!(access_token_maximum_lifetime_secs),
        );
    }
    if !operator_auth.is_empty() {
        honeypot.insert("OperatorAuth".to_owned(), Value::Object(operator_auth));
    }

    let mut kill_switch = Map::new();
    if let Some(enable_session_kill) = honeypot_config.enable_session_kill {
        kill_switch.insert("EnableSessionKill".to_owned(), json!(enable_session_kill));
    }
    if let Some(enable_system_kill) = honeypot_config.enable_system_kill {
        kill_switch.insert("EnableSystemKill".to_owned(), json!(enable_system_kill));
    }
    if let Some(halt_new_sessions_on_system_kill) = honeypot_config.halt_new_sessions_on_system_kill {
        kill_switch.insert(
            "HaltNewSessionsOnSystemKill".to_owned(),
            json!(halt_new_sessions_on_system_kill),
        );
    }
    if !kill_switch.is_empty() {
        honeypot.insert("KillSwitch".to_owned(), Value::Object(kill_switch));
    }

    let mut frontend = Map::new();
    if let Some(public_url) = honeypot_config.frontend_public_url {
        frontend.insert("PublicUrl".to_owned(), json!(public_url));
    }
    if let Some(bootstrap_path) = honeypot_config.frontend_bootstrap_path {
        frontend.insert("BootstrapPath".to_owned(), json!(bootstrap_path));
    }
    if let Some(events_path) = honeypot_config.frontend_events_path {
        frontend.insert("EventsPath".to_owned(), json!(events_path));
    }
    if !frontend.is_empty() {
        honeypot.insert("Frontend".to_owned(), Value::Object(frontend));
    }

    Value::Object(honeypot)
}

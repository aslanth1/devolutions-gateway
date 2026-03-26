use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::DgwState;
use crate::honeypot::{HoneypotDependencyServiceState, HoneypotProxyHealthSnapshot, HoneypotProxyServiceState};

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct Identity {
    /// This Gateway's unique ID
    id: Option<Uuid>,
    /// This Gateway's hostname
    hostname: String,
    /// Gateway service version
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'static str>,
    /// Honeypot dependency state when honeypot mode is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    honeypot: Option<HoneypotHealth>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HoneypotHealthState {
    Ready,
    Degraded,
    Unavailable,
}

impl From<HoneypotProxyServiceState> for HoneypotHealthState {
    fn from(value: HoneypotProxyServiceState) -> Self {
        match value {
            HoneypotProxyServiceState::Ready => Self::Ready,
            HoneypotProxyServiceState::Degraded => Self::Degraded,
            HoneypotProxyServiceState::Unavailable => Self::Unavailable,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HoneypotDependencyHealthState {
    Ready,
    Degraded,
    Unsafe,
}

impl From<HoneypotDependencyServiceState> for HoneypotDependencyHealthState {
    fn from(value: HoneypotDependencyServiceState) -> Self {
        match value {
            HoneypotDependencyServiceState::Ready => Self::Ready,
            HoneypotDependencyServiceState::Degraded => Self::Degraded,
            HoneypotDependencyServiceState::Unsafe => Self::Unsafe,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct HoneypotHealth {
    honeypot_enabled: bool,
    service_state: HoneypotHealthState,
    control_plane_reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    control_plane_service_state: Option<HoneypotDependencyHealthState>,
    degraded_reasons: Vec<String>,
}

pub(super) enum HealthResponse {
    Identity {
        status: StatusCode,
        body: Identity,
    },
    /// Legacy response for DVLS prior to 2022.3.x
    // TODO(axum): REST API compatibility tests
    HealthyMessage(String),
}

impl IntoResponse for HealthResponse {
    fn into_response(self) -> Response {
        match self {
            HealthResponse::Identity { status, body } => (status, Json(body)).into_response(),
            HealthResponse::HealthyMessage(message) => message.into_response(),
        }
    }
}

/// Performs a health check
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetHealth",
    tag = "Health",
    path = "/jet/health",
    responses(
        (status = 200, description = "Identity for this Gateway", body = Identity),
        (status = 503, description = "Gateway listener is up but honeypot dependencies are degraded", body = Identity),
        (status = 400, description = "Invalid Accept header"),
    ),
))]
pub(super) async fn get_health(State(state): State<DgwState>, headers: HeaderMap) -> HealthResponse {
    let conf = state.conf_handle.get_conf();

    if accepts_json(&headers) {
        let honeypot = state.honeypot.health_snapshot().await.map(honeypot_health_response);
        let status = if matches!(
            honeypot.as_ref().map(|health| &health.service_state),
            Some(&HoneypotHealthState::Degraded) | Some(&HoneypotHealthState::Unavailable)
        ) {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        };

        return HealthResponse::Identity {
            status,
            body: Identity {
                id: conf.id,
                hostname: conf.hostname.clone(),
                version: Some(env!("CARGO_PKG_VERSION")),
                honeypot,
            },
        };
    }

    HealthResponse::HealthyMessage(format!(
        "Devolutions Gateway \"{}\" is alive and healthy.",
        conf.hostname
    ))
}

fn accepts_json(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|hval| hval.to_str().ok())
        .into_iter()
        .flat_map(|hval| hval.split(','))
        .any(|hval| hval.trim() == "application/json")
}

fn honeypot_health_response(snapshot: HoneypotProxyHealthSnapshot) -> HoneypotHealth {
    HoneypotHealth {
        honeypot_enabled: true,
        service_state: snapshot.service_state.into(),
        control_plane_reachable: snapshot.control_plane_reachable,
        control_plane_service_state: snapshot.control_plane_service_state.map(Into::into),
        degraded_reasons: snapshot.degraded_reasons,
    }
}

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use honeypot_contracts::Versioned;
use honeypot_contracts::frontend::{
    CommandProposalRequest, CommandProposalResponse, CommandProposalState, CommandVoteChoice, CommandVoteRequest,
    CommandVoteResponse, CommandVoteState, KeyboardCaptureRequest, KeyboardCaptureResponse, KeyboardCaptureState,
};
use uuid::Uuid;

use crate::DgwState;
use crate::extract::ScopeToken;
use crate::http::HttpError;
use crate::session::{KillResult, SessionKillMetadata};
use crate::token::AccessScope;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/system/terminate", post(terminate_all_sessions))
        .route("/{id}/keyboard", post(capture_keyboard))
        .route("/{id}/propose", post(propose_command))
        .route("/{id}/vote", post(vote_command))
        .route("/{id}/quarantine", post(quarantine_session))
        .route("/{id}/terminate", post(terminate_session))
        .with_state(state)
}

/// Terminate forcefully a running session
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "TerminateSession",
    tag = "Sessions",
    path = "/jet/session/{id}/terminate",
    params(
        ("id" = Uuid, Path, description = "Session / association ID of the session to terminate")
    ),
    responses(
        (status = 200, description = "Session terminated successfully"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "No running session found with provided ID"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("scope_token" = ["gateway.session.terminate"])),
))]
pub(crate) async fn terminate_session(
    State(state): State<DgwState>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    scope_token: ScopeToken,
) -> Result<(), HttpError> {
    let kill_metadata = authorize_terminate_scope(&state, &scope_token)?;

    let kill_result = match kill_metadata {
        Some(kill_metadata) => {
            state
                .sessions
                .kill_session_with_metadata(session_id, kill_metadata)
                .await
        }
        None => state.sessions.kill_session(session_id).await,
    }
    .map_err(HttpError::internal().err())?;

    match kill_result {
        KillResult::Success => Ok(()),
        KillResult::NotFound => Err(HttpError::not_found().msg("session not found")),
    }
}

/// Quarantine forcefully a running honeypot session and its guest lease
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "QuarantineSession",
    tag = "Sessions",
    path = "/jet/session/{id}/quarantine",
    params(
        ("id" = Uuid, Path, description = "Session / association ID of the honeypot session to quarantine")
    ),
    responses(
        (status = 200, description = "Session quarantine requested successfully"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "No running honeypot session found with provided ID"),
        (status = 409, description = "Honeypot session kill is disabled"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("scope_token" = ["gateway.honeypot.session.kill"])),
))]
pub(crate) async fn quarantine_session(
    State(state): State<DgwState>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    scope_token: ScopeToken,
) -> Result<(), HttpError> {
    if !state.honeypot.is_enabled() {
        return Err(HttpError::not_found().msg("honeypot mode is disabled"));
    }

    let conf = state.conf_handle.get_conf();
    ensure_honeypot_session_kill_enabled(&conf)?;

    let kill_metadata = authorize_quarantine_scope(&scope_token)?;
    let kill_result = state
        .sessions
        .kill_session_with_metadata(session_id, kill_metadata)
        .await
        .map_err(HttpError::internal().err())?;

    match kill_result {
        KillResult::Success => Ok(()),
        KillResult::NotFound => Err(HttpError::not_found().msg("session not found")),
    }
}

#[derive(Serialize)]
pub(crate) struct SystemTerminateResponse {
    system_kill_active: bool,
    halt_new_sessions: bool,
    terminated_sessions_requested: usize,
}

async fn propose_command(
    State(state): State<DgwState>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    scope_token: ScopeToken,
    Json(request): Json<CommandProposalRequest>,
) -> Result<Json<CommandProposalResponse>, HttpError> {
    if !state.honeypot.is_enabled() {
        return Err(HttpError::not_found().msg("honeypot mode is disabled"));
    }

    authorize_proposal_scope(&scope_token)?;
    request.ensure_supported_schema().map_err(
        HttpError::bad_request()
            .with_msg("unsupported honeypot schema_version")
            .err(),
    )?;

    let trimmed_command = request.command_text.trim().to_owned();
    let proposal_state = if trimmed_command.is_empty() {
        CommandProposalState::Rejected
    } else {
        CommandProposalState::Deferred
    };
    let decision_reason = if trimmed_command.is_empty() {
        "empty_command"
    } else {
        "disabled_by_policy"
    };
    let response = CommandProposalResponse {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        correlation_id: format!("honeypot-command-proposal-{}", Uuid::new_v4()),
        proposal_id: format!("proposal-{}", Uuid::new_v4()),
        recorded_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        session_id: session_id.to_string(),
        command_text: trimmed_command,
        proposal_state,
        decision_reason: decision_reason.to_owned(),
        executed: false,
    };

    tracing::info!(
        session_id = %response.session_id,
        proposal_id = %response.proposal_id,
        correlation_id = %response.correlation_id,
        proposal_state = ?response.proposal_state,
        decision_reason = %response.decision_reason,
        executed = response.executed,
        "honeypot command proposal placeholder recorded"
    );

    Ok(Json(response))
}

async fn vote_command(
    State(state): State<DgwState>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    scope_token: ScopeToken,
    Json(request): Json<CommandVoteRequest>,
) -> Result<Json<CommandVoteResponse>, HttpError> {
    if !state.honeypot.is_enabled() {
        return Err(HttpError::not_found().msg("honeypot mode is disabled"));
    }

    authorize_vote_scope(&scope_token)?;
    request.ensure_supported_schema().map_err(
        HttpError::bad_request()
            .with_msg("unsupported honeypot schema_version")
            .err(),
    )?;

    let proposal_id = request.proposal_id.trim().to_owned();
    if proposal_id.is_empty() {
        return Err(HttpError::bad_request().msg("proposal_id is required"));
    }

    let (vote_state, decision_reason) = match request.vote {
        CommandVoteChoice::Approve => (CommandVoteState::Deferred, "disabled_by_policy"),
        CommandVoteChoice::Reject => (CommandVoteState::Rejected, "rejected_by_operator"),
    };

    let response = CommandVoteResponse {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        correlation_id: format!("honeypot-command-vote-{}", Uuid::new_v4()),
        vote_id: format!("vote-{}", Uuid::new_v4()),
        recorded_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        session_id: session_id.to_string(),
        proposal_id,
        vote: request.vote,
        vote_state,
        decision_reason: decision_reason.to_owned(),
        executed: false,
    };

    tracing::info!(
        session_id = %response.session_id,
        proposal_id = %response.proposal_id,
        vote_id = %response.vote_id,
        correlation_id = %response.correlation_id,
        vote = ?response.vote,
        vote_state = ?response.vote_state,
        decision_reason = %response.decision_reason,
        executed = response.executed,
        "honeypot command vote placeholder recorded"
    );

    Ok(Json(response))
}

async fn capture_keyboard(
    State(state): State<DgwState>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    scope_token: ScopeToken,
    Json(request): Json<KeyboardCaptureRequest>,
) -> Result<Json<KeyboardCaptureResponse>, HttpError> {
    if !state.honeypot.is_enabled() {
        return Err(HttpError::not_found().msg("honeypot mode is disabled"));
    }

    authorize_keyboard_scope(&scope_token)?;
    request.ensure_supported_schema().map_err(
        HttpError::bad_request()
            .with_msg("unsupported honeypot schema_version")
            .err(),
    )?;

    let requested_key_count = u32::try_from(request.key_sequence.chars().count()).unwrap_or(u32::MAX);
    let response = KeyboardCaptureResponse {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        correlation_id: format!("honeypot-keyboard-capture-{}", Uuid::new_v4()),
        capture_id: format!("keyboard-{}", Uuid::new_v4()),
        recorded_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        session_id: session_id.to_string(),
        requested_key_count,
        capture_state: KeyboardCaptureState::DisabledByPolicy,
        decision_reason: "disabled_by_policy".to_owned(),
        executed: false,
    };

    tracing::info!(
        session_id = %response.session_id,
        capture_id = %response.capture_id,
        correlation_id = %response.correlation_id,
        requested_key_count = response.requested_key_count,
        capture_state = ?response.capture_state,
        decision_reason = %response.decision_reason,
        executed = response.executed,
        "honeypot keyboard capture placeholder recorded"
    );

    Ok(Json(response))
}

async fn terminate_all_sessions(
    State(state): State<DgwState>,
    scope_token: ScopeToken,
) -> Result<Json<SystemTerminateResponse>, HttpError> {
    if !state.honeypot.is_enabled() {
        return Err(HttpError::not_found().msg("honeypot mode is disabled"));
    }

    let conf = state.conf_handle.get_conf();
    ensure_honeypot_system_kill_enabled(&conf)?;
    let kill_metadata = authorize_system_terminate_scope(&scope_token)?;

    state.honeypot.activate_system_kill();

    let terminated_sessions_requested = state
        .sessions
        .kill_all_sessions_with_metadata(kill_metadata)
        .await
        .map_err(HttpError::internal().err())?;

    Ok(Json(SystemTerminateResponse {
        system_kill_active: true,
        halt_new_sessions: conf.honeypot.kill_switch.halt_new_sessions_on_system_kill,
        terminated_sessions_requested,
    }))
}

fn authorize_terminate_scope(
    state: &DgwState,
    scope_token: &ScopeToken,
) -> Result<Option<SessionKillMetadata>, HttpError> {
    let conf = state.conf_handle.get_conf();
    let scope = &scope_token.0.scope;

    if matches!(scope, AccessScope::Wildcard | AccessScope::SessionTerminate) {
        return if state.honeypot.is_enabled() {
            ensure_honeypot_session_kill_enabled(&conf)?;
            Ok(Some(SessionKillMetadata::operator(scope_token.0.token_id())))
        } else {
            Ok(None)
        };
    }

    if !state.honeypot.is_enabled() {
        return Err(HttpError::forbidden().msg("invalid scope for route"));
    }

    ensure_honeypot_session_kill_enabled(&conf)?;

    match scope {
        AccessScope::HoneypotSessionKill | AccessScope::HoneypotSystemKill => {
            Ok(Some(SessionKillMetadata::operator(scope_token.0.token_id())))
        }
        _ => Err(HttpError::forbidden().msg("invalid scope for route")),
    }
}

fn ensure_honeypot_session_kill_enabled(conf: &crate::config::Conf) -> Result<(), HttpError> {
    if conf.honeypot.kill_switch.enable_session_kill {
        Ok(())
    } else {
        Err(HttpError::conflict().msg("honeypot session kill is disabled"))
    }
}

fn authorize_system_terminate_scope(scope_token: &ScopeToken) -> Result<SessionKillMetadata, HttpError> {
    match scope_token.0.scope {
        AccessScope::Wildcard | AccessScope::HoneypotSystemKill => {
            Ok(SessionKillMetadata::system_operator(scope_token.0.token_id()))
        }
        _ => Err(HttpError::forbidden().msg("invalid scope for route")),
    }
}

fn authorize_quarantine_scope(scope_token: &ScopeToken) -> Result<SessionKillMetadata, HttpError> {
    match scope_token.0.scope {
        AccessScope::Wildcard | AccessScope::HoneypotSessionKill | AccessScope::HoneypotSystemKill => {
            Ok(SessionKillMetadata::operator_quarantine(scope_token.0.token_id()))
        }
        _ => Err(HttpError::forbidden().msg("invalid scope for route")),
    }
}

fn authorize_proposal_scope(scope_token: &ScopeToken) -> Result<(), HttpError> {
    match scope_token.0.scope {
        AccessScope::Wildcard | AccessScope::HoneypotCommandPropose => Ok(()),
        _ => Err(HttpError::forbidden().msg("invalid scope for route")),
    }
}

fn authorize_vote_scope(scope_token: &ScopeToken) -> Result<(), HttpError> {
    match scope_token.0.scope {
        AccessScope::Wildcard | AccessScope::HoneypotCommandApprove => Ok(()),
        _ => Err(HttpError::forbidden().msg("invalid scope for route")),
    }
}

fn authorize_keyboard_scope(scope_token: &ScopeToken) -> Result<(), HttpError> {
    match scope_token.0.scope {
        AccessScope::Wildcard | AccessScope::HoneypotCommandApprove => Ok(()),
        _ => Err(HttpError::forbidden().msg("invalid scope for route")),
    }
}

fn ensure_honeypot_system_kill_enabled(conf: &crate::config::Conf) -> Result<(), HttpError> {
    if conf.honeypot.kill_switch.enable_system_kill {
        Ok(())
    } else {
        Err(HttpError::conflict().msg("honeypot system kill is disabled"))
    }
}

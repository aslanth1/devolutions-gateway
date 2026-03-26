use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use devolutions_gateway::token::{AccessScope, AccessTokenClaims, ContentType};
use honeypot_contracts::auth::CONTROL_PLANE_SCOPE;
use picky::jose::jws::RawJws;
use picky::jose::jwt::{JwtDate, JwtSig, JwtValidator, NO_CHECK_VALIDATOR};
use picky::key::PublicKey;
use serde_json::Value;

use crate::config::AuthConfig;

const TOKEN_VALIDATION_LEEWAY_SECS: u16 = 60 * 5;

#[derive(Debug, Clone)]
pub(super) struct ControlPlaneAuth {
    validation: ValidationMode,
}

#[derive(Debug, Clone)]
enum ValidationMode {
    Disabled,
    Verified { proxy_verifier_public_key: PublicKey },
}

#[derive(Debug)]
pub(super) enum AuthError {
    MissingToken,
    InvalidToken(anyhow::Error),
    Forbidden { actual: AccessScope },
}

impl ControlPlaneAuth {
    pub(super) fn from_config(config: &AuthConfig) -> anyhow::Result<Self> {
        let validation = if config.service_token_validation_disabled {
            ValidationMode::Disabled
        } else {
            let pem = config
                .proxy_verifier_public_key_pem
                .as_deref()
                .context("missing auth.proxy_verifier_public_key_pem while control-plane auth is enabled")?;
            let proxy_verifier_public_key =
                PublicKey::from_pem_str(pem).context("parse auth.proxy_verifier_public_key_pem")?;

            ValidationMode::Verified {
                proxy_verifier_public_key,
            }
        };

        Ok(Self { validation })
    }

    pub(super) fn authorize(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        let raw_token = extract_bearer_token(headers).ok_or(AuthError::MissingToken)?;
        let scope = match &self.validation {
            ValidationMode::Disabled => validate_scope_token_disabled(raw_token)?,
            ValidationMode::Verified {
                proxy_verifier_public_key,
            } => validate_scope_token_verified(raw_token, proxy_verifier_public_key)?,
        };

        if scope_allows(&scope) {
            Ok(())
        } else {
            Err(AuthError::Forbidden { actual: scope })
        }
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();

    if token.is_empty() { None } else { Some(token) }
}

fn validate_scope_token_disabled(token: &str) -> Result<AccessScope, AuthError> {
    let raw_jws = RawJws::decode(token)
        .context("parse service token")
        .map_err(AuthError::InvalidToken)?;
    let jwt = JwtSig::from(raw_jws.discard_signature());
    let claims = jwt
        .validate::<Value>(&NO_CHECK_VALIDATOR)
        .context("decode service token without signature validation")
        .map_err(AuthError::InvalidToken)?
        .state
        .claims;
    let claims = serde_json::from_value::<AccessTokenClaims>(claims)
        .context("decode service token claims")
        .map_err(AuthError::InvalidToken)?;

    extract_scope(claims)
}

fn validate_scope_token_verified(token: &str, proxy_verifier_public_key: &PublicKey) -> Result<AccessScope, AuthError> {
    let raw_jws = RawJws::decode(token)
        .context("parse service token")
        .map_err(AuthError::InvalidToken)?;
    let jwt = raw_jws
        .verify(proxy_verifier_public_key)
        .map(JwtSig::from)
        .context("verify service token signature")
        .map_err(AuthError::InvalidToken)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system time for service token validation")
        .map_err(AuthError::InvalidToken)?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| {
        AuthError::InvalidToken(anyhow::anyhow!(
            "system clock exceeds supported service token validation range"
        ))
    })?;
    let validator = JwtValidator::strict(JwtDate::new_with_leeway(now, TOKEN_VALIDATION_LEEWAY_SECS));

    let (claims, content_type) = if let Some(content_type) = jwt.header.cty.as_deref() {
        let content_type = ContentType::from_str(content_type)
            .context("parse service token content type")
            .map_err(AuthError::InvalidToken)?;
        let claims = jwt
            .validate::<Value>(&validator)
            .context("validate service token claims")
            .map_err(AuthError::InvalidToken)?
            .state
            .claims;
        (claims, content_type)
    } else {
        let mut claims = jwt
            .validate::<Value>(&validator)
            .context("validate service token claims")
            .map_err(AuthError::InvalidToken)?
            .state
            .claims;
        let content_type = match claims.get_mut("type") {
            Some(Value::String(content_type)) => {
                content_type.make_ascii_uppercase();
                ContentType::from_str(content_type)
                    .context("parse service token type claim")
                    .map_err(AuthError::InvalidToken)?
            }
            _ => {
                return Err(AuthError::InvalidToken(anyhow::anyhow!(
                    "service token content type is missing"
                )));
            }
        };
        (claims, content_type)
    };

    if !matches!(content_type, ContentType::Scope) {
        return Err(AuthError::InvalidToken(anyhow::anyhow!(
            "service token is not a scope token"
        )));
    }

    let claims = serde_json::from_value::<AccessTokenClaims>(claims)
        .context("decode service token claims")
        .map_err(AuthError::InvalidToken)?;

    extract_scope(claims)
}

fn extract_scope(claims: AccessTokenClaims) -> Result<AccessScope, AuthError> {
    match claims {
        AccessTokenClaims::Scope(claims) => Ok(claims.scope),
        _ => Err(AuthError::InvalidToken(anyhow::anyhow!(
            "service token is not a scope token"
        ))),
    }
}

fn scope_allows(actual: &AccessScope) -> bool {
    matches!(actual, AccessScope::Wildcard | AccessScope::HoneypotControlPlane)
}

impl AuthError {
    pub(super) fn message(&self) -> String {
        match self {
            Self::MissingToken => "service token is missing".to_owned(),
            Self::InvalidToken(error) => format!("service token is invalid: {error:#}"),
            Self::Forbidden { actual } => {
                format!("service token scope {actual:?} does not satisfy required scope {CONTROL_PLANE_SCOPE}")
            }
        }
    }
}

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use devolutions_gateway::token::{AccessScope, AccessTokenClaims, ContentType};
use picky::jose::jws::RawJws;
use picky::jose::jwt::{JwtDate, JwtSig, JwtValidator, NO_CHECK_VALIDATOR};
use picky::key::PublicKey;
use serde_json::Value;

use crate::config::AuthConfig;

const TOKEN_VALIDATION_LEEWAY_SECS: u16 = 60 * 5;

#[derive(Clone)]
pub(super) struct FrontendAuth {
    validation: ValidationMode,
}

#[derive(Clone)]
enum ValidationMode {
    Disabled,
    Verified { provisioner_public_key: PublicKey },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequiredScope {
    Watch,
    StreamRead,
}

impl RequiredScope {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Watch => "gateway.honeypot.watch",
            Self::StreamRead => "gateway.honeypot.stream.read",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct OperatorAccess {
    raw_token: String,
}

impl OperatorAccess {
    pub(super) fn raw_token(&self) -> &str {
        &self.raw_token
    }
}

#[derive(Debug)]
pub(super) enum AuthError {
    MissingToken,
    InvalidToken(anyhow::Error),
    Forbidden {
        required: RequiredScope,
        actual: AccessScope,
    },
}

impl FrontendAuth {
    pub(super) fn from_config(config: &AuthConfig) -> anyhow::Result<Self> {
        let validation = if config.operator_token_validation_disabled {
            ValidationMode::Disabled
        } else {
            let pem = config
                .operator_verifier_public_key_pem
                .as_deref()
                .context("missing auth.operator_verifier_public_key_pem while operator auth is enabled")?;
            let provisioner_public_key =
                PublicKey::from_pem_str(pem).context("parse auth.operator_verifier_public_key_pem")?;

            ValidationMode::Verified { provisioner_public_key }
        };

        Ok(Self { validation })
    }

    pub(super) fn authorize(
        &self,
        headers: &HeaderMap,
        query_token: Option<&str>,
        required: RequiredScope,
    ) -> Result<OperatorAccess, AuthError> {
        let raw_token = extract_operator_token(headers, query_token).ok_or(AuthError::MissingToken)?;
        let scope = match &self.validation {
            ValidationMode::Disabled => validate_scope_token_disabled(raw_token)?,
            ValidationMode::Verified { provisioner_public_key } => {
                validate_scope_token_verified(raw_token, provisioner_public_key)?
            }
        };

        if scope_allows(required, &scope) {
            Ok(OperatorAccess {
                raw_token: raw_token.to_owned(),
            })
        } else {
            Err(AuthError::Forbidden {
                required,
                actual: scope,
            })
        }
    }
}

fn extract_operator_token<'a>(headers: &'a HeaderMap, query_token: Option<&'a str>) -> Option<&'a str> {
    if let Some(value) = headers.get(AUTHORIZATION)
        && let Ok(value) = value.to_str()
        && let Some(token) = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))
    {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token);
        }
    }

    query_token.filter(|token| !token.is_empty())
}

fn validate_scope_token_disabled(token: &str) -> Result<AccessScope, AuthError> {
    let raw_jws = RawJws::decode(token)
        .context("parse operator token")
        .map_err(AuthError::InvalidToken)?;
    let jwt = JwtSig::from(raw_jws.discard_signature());
    let claims = jwt
        .validate::<Value>(&NO_CHECK_VALIDATOR)
        .context("decode operator token without signature validation")
        .map_err(AuthError::InvalidToken)?
        .state
        .claims;
    let claims = serde_json::from_value::<AccessTokenClaims>(claims)
        .context("decode operator token claims")
        .map_err(AuthError::InvalidToken)?;

    extract_scope(claims)
}

fn validate_scope_token_verified(token: &str, provisioner_public_key: &PublicKey) -> Result<AccessScope, AuthError> {
    let raw_jws = RawJws::decode(token)
        .context("parse operator token")
        .map_err(AuthError::InvalidToken)?;
    let jwt = raw_jws
        .verify(provisioner_public_key)
        .map(JwtSig::from)
        .context("verify operator token signature")
        .map_err(AuthError::InvalidToken)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system time for operator token validation")
        .map_err(AuthError::InvalidToken)?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| {
        AuthError::InvalidToken(anyhow::anyhow!(
            "system clock exceeds supported operator token validation range"
        ))
    })?;
    let validator = JwtValidator::strict(JwtDate::new_with_leeway(now, TOKEN_VALIDATION_LEEWAY_SECS));

    let (claims, content_type) = if let Some(content_type) = jwt.header.cty.as_deref() {
        let content_type = ContentType::from_str(content_type)
            .context("parse operator token content type")
            .map_err(AuthError::InvalidToken)?;
        let claims = jwt
            .validate::<Value>(&validator)
            .context("validate operator token claims")
            .map_err(AuthError::InvalidToken)?
            .state
            .claims;
        (claims, content_type)
    } else {
        let mut claims = jwt
            .validate::<Value>(&validator)
            .context("validate operator token claims")
            .map_err(AuthError::InvalidToken)?
            .state
            .claims;
        let content_type = match claims.get_mut("type") {
            Some(Value::String(content_type)) => {
                content_type.make_ascii_uppercase();
                ContentType::from_str(content_type)
                    .context("parse operator token type claim")
                    .map_err(AuthError::InvalidToken)?
            }
            _ => {
                return Err(AuthError::InvalidToken(anyhow::anyhow!(
                    "operator token content type is missing"
                )));
            }
        };
        (claims, content_type)
    };

    if !matches!(content_type, ContentType::Scope) {
        return Err(AuthError::InvalidToken(anyhow::anyhow!(
            "operator token is not a scope token"
        )));
    }

    let claims = serde_json::from_value::<AccessTokenClaims>(claims)
        .context("decode operator token claims")
        .map_err(AuthError::InvalidToken)?;

    extract_scope(claims)
}

fn extract_scope(claims: AccessTokenClaims) -> Result<AccessScope, AuthError> {
    match claims {
        AccessTokenClaims::Scope(claims) => Ok(claims.scope),
        _ => Err(AuthError::InvalidToken(anyhow::anyhow!(
            "operator token is not a scope token"
        ))),
    }
}

fn scope_allows(required: RequiredScope, actual: &AccessScope) -> bool {
    matches!(
        (required, actual),
        (_, AccessScope::Wildcard)
            | (RequiredScope::Watch, AccessScope::HoneypotWatch)
            | (RequiredScope::Watch, AccessScope::HoneypotStreamRead)
            | (RequiredScope::StreamRead, AccessScope::HoneypotStreamRead)
    )
}

use std::path::Path;
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
            let pem = resolve_proxy_verifier_public_key_pem(config)?;
            let proxy_verifier_public_key = PublicKey::from_pem_str(&pem)
                .context("parse auth.proxy_verifier_public_key_pem or file-backed secret")?;

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

fn resolve_proxy_verifier_public_key_pem(config: &AuthConfig) -> anyhow::Result<String> {
    if let Some(path) = config.proxy_verifier_public_key_pem_file.as_deref() {
        return read_required_secret_file(path, "auth.proxy_verifier_public_key_pem_file");
    }

    config
        .proxy_verifier_public_key_pem
        .clone()
        .context("missing auth.proxy_verifier_public_key_pem_file or auth.proxy_verifier_public_key_pem while control-plane auth is enabled")
}

fn read_required_secret_file(path: &Path, field_name: &str) -> anyhow::Result<String> {
    let secret = std::fs::read_to_string(path).with_context(|| format!("read {field_name} from {}", path.display()))?;
    let secret = secret.trim();

    anyhow::ensure!(
        !secret.is_empty(),
        "{field_name} at {} must not be empty",
        path.display(),
    );

    Ok(secret.to_owned())
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

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use picky::jose::jws::JwsAlg;
    use picky::jose::jwt::CheckedJwtSig;
    use picky::key::PrivateKey;

    use super::*;

    const PROXY_SIGNING_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDkrPiL/5dmGIT5
/KuC3H/jIjeLoLoddsLhAlikO5JQQo3Zs71GwT4Wd2z8WLMe0lVZu/Jr2S28p0M8
F3Lnz4IgzjocQomFgucFWWQRyD03ZE2BHfEeelFsp+/4GZaM6lKZauYlIMtjR1vD
lflgvxNTr0iaii4JR9K3IKCunCRy1HQYPcZ9waNtlG5xXtW9Uf1tLWPJpP/3I5HL
M85JPBv4r286vpeUlfQIa/NB4g5w6KZ6MfEAIU4KeEQpeLAyyYvwUzPR2uQZ4y4I
4Nj84dWYB1cMTlSGugvSgOFKYit1nwLGeA7EevVYPbILRfSMBU/+avGNJJ8HCaaq
FIyY42W9AgMBAAECggEBAImsGXcvydaNrIFUvW1rkxML5qUJfwN+HJWa9ALsWoo3
h28p5ypR7S9ZdyP1wuErgHcl0C1d80tA6BmlhGhLZeyaPCIHbQQUa0GtL7IE+9X9
bSvu+tt+iMcB1FdqEFmGOXRkB2sS82Ax9e0qvZihcOFRBkUEK/MqapIV8qctGkSG
wIE6yn5LHRls/fJU8BJeeqJmYpuWljipwTkp9hQ7SdRYFLNjwjlz/b0hjmgFs5QZ
LUNMyTHdHtXQHNsf/GayRUAKf5wzN/jru+nK6lMob2Ehfx9/RAfgaDHzy5BNFMj0
i9+sAycgIW1HpTuDvSEs3qP26NeQ82GbJzATmdAKa4ECgYEA9Vti0YG+eXJI3vdS
uXInU0i1SY4aEG397OlGMwh0yQnp2KGruLZGkTvqxG/Adj1ObDyjFH9XUhMrd0za
Nk/VJFybWafljUPcrfyPAVLQLjsBfMg3Y34sTF6QjUnhg49X2jfvy9QpC5altCtA
46/KVAGREnQJ3wMjfGGIFP8BUZsCgYEA7phYE/cYyWg7a/o8eKOFGqs11ojSqG3y
0OE7kvW2ugUuy3ex+kr19Q/8pOWEc7M1UEV8gmc11xgB70EhIFt9Jq379H0X4ahS
+mgLiPzKAdNCRPpkxwwN9HxFDgGWoYcgMplhoAmg9lWSDuE1Exy8iu5inMWuF4MT
/jG+cLnUZ4cCgYAfMIXIUjDvaUrAJTp73noHSUfaWNkRW5oa4rCMzjdiUwNKCYs1
yN4BmldGr1oM7dApTDAC7AkiotM0sC1RGCblH2yUIha5NXY5G9Dl/yv9pHyU6zK3
UBO7hY3kmA611aP6VoACLi8ljPn1hEYUa4VR1n0llmCm29RH/HH7EUuOnwKBgExH
OCFp5eq+AAFNRvfqjysvgU7M/0wJmo9c8obRN1HRRlyWL7gtLuTh74toNSgoKus2
y8+E35mce0HaOJT3qtMq3FoVhAUIoz6a9NUevBZJS+5xfraEDBIViJ4ps9aANLL4
hlV7vpICWWeYaDdsAHsKK0yjhjzOEx45GQFA578RAoGBAOB42BG53tL0G9pPeJPt
S2LM6vQKeYx+gXTk6F335UTiiC8t0CgNNQUkW105P/SdpCTTKojAsOPMKOF7z4mL
lj/bWmNq7xu9uVOcBKrboVFGO/n6FXyWZxHPOTdjTkpe8kvvmSwl2iaTNllvSr46
Z/fDKMxHxeXla54kfV+HiGkH
-----END PRIVATE KEY-----"#;

    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("honeypot-control-plane-auth-{label}-{}.pem", nanos))
    }

    fn signed_control_plane_scope_token() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_secs() as i64;
        let claims = serde_json::json!({
            "type": "scope",
            "scope": CONTROL_PLANE_SCOPE,
            "iat": now - 60,
            "nbf": now - 60,
            "exp": now + 3600,
            "jti": "00000000-0000-0000-0000-000000000101"
        });
        let signing_key = PrivateKey::from_pem_str(PROXY_SIGNING_KEY_PEM).expect("parse proxy signing key");
        let token = CheckedJwtSig::new_with_cty(JwsAlg::RS256, ContentType::Scope.to_string(), &claims);
        token
            .encode(&signing_key)
            .expect("encode signed control-plane scope token")
    }

    fn verified_auth_config(path: std::path::PathBuf) -> AuthConfig {
        AuthConfig {
            service_token_validation_disabled: false,
            proxy_verifier_public_key_pem: None,
            proxy_verifier_public_key_pem_file: Some(path),
        }
    }

    #[test]
    fn verified_auth_reads_proxy_verifier_key_from_secret_file() {
        let secret_path = unique_temp_path("proxy-verifier-public-key");
        let signing_key = PrivateKey::from_pem_str(PROXY_SIGNING_KEY_PEM).expect("parse proxy signing key");
        let public_key = signing_key
            .to_public_key()
            .expect("derive public key")
            .to_pem_str()
            .expect("encode public key pem");
        std::fs::write(&secret_path, format!("{public_key}\n")).expect("write verifier public key");

        let auth = ControlPlaneAuth::from_config(&verified_auth_config(secret_path.clone()))
            .expect("build verified control-plane auth");

        let mut headers = HeaderMap::new();
        let token = signed_control_plane_scope_token();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("authorization header"),
        );

        auth.authorize(&headers)
            .expect("authorize signed control-plane scope token from secret file");

        std::fs::remove_file(secret_path).expect("remove verifier public key");
    }

    #[test]
    fn verified_auth_rejects_missing_proxy_verifier_key_file() {
        let secret_path = unique_temp_path("missing-proxy-verifier-public-key");
        let error = ControlPlaneAuth::from_config(&verified_auth_config(secret_path))
            .expect_err("missing proxy verifier key file should fail");

        assert!(
            format!("{error:#}").contains("proxy_verifier_public_key_pem_file"),
            "{error:#}"
        );
    }

    #[test]
    fn verified_auth_rejects_empty_proxy_verifier_key_file() {
        let secret_path = unique_temp_path("empty-proxy-verifier-public-key");
        std::fs::write(&secret_path, "\n").expect("write empty verifier public key file");

        let error = ControlPlaneAuth::from_config(&verified_auth_config(secret_path.clone()))
            .expect_err("empty proxy verifier key file should fail");

        assert!(format!("{error:#}").contains("must not be empty"), "{error:#}");

        std::fs::remove_file(secret_path).expect("remove empty verifier public key file");
    }
}

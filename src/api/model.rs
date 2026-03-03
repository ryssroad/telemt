use chrono::{DateTime, Utc};
use hyper::StatusCode;
use rand::Rng;
use serde::{Deserialize, Serialize};

const MAX_USERNAME_LEN: usize = 64;

#[derive(Debug)]
pub(super) struct ApiFailure {
    pub(super) status: StatusCode,
    pub(super) code: &'static str,
    pub(super) message: String,
}

impl ApiFailure {
    pub(super) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub(super) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }

    pub(super) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
}

#[derive(Serialize)]
pub(super) struct ErrorBody {
    pub(super) code: &'static str,
    pub(super) message: String,
}

#[derive(Serialize)]
pub(super) struct ErrorResponse {
    pub(super) ok: bool,
    pub(super) error: ErrorBody,
    pub(super) request_id: u64,
}

#[derive(Serialize)]
pub(super) struct SuccessResponse<T> {
    pub(super) ok: bool,
    pub(super) data: T,
    pub(super) revision: String,
}

#[derive(Serialize)]
pub(super) struct HealthData {
    pub(super) status: &'static str,
    pub(super) read_only: bool,
}

#[derive(Serialize)]
pub(super) struct SummaryData {
    pub(super) uptime_seconds: f64,
    pub(super) connections_total: u64,
    pub(super) connections_bad_total: u64,
    pub(super) handshake_timeouts_total: u64,
    pub(super) configured_users: usize,
}

#[derive(Serialize)]
pub(super) struct UserInfo {
    pub(super) username: String,
    pub(super) user_ad_tag: Option<String>,
    pub(super) max_tcp_conns: Option<usize>,
    pub(super) expiration_rfc3339: Option<String>,
    pub(super) data_quota_bytes: Option<u64>,
    pub(super) max_unique_ips: Option<usize>,
    pub(super) current_connections: u64,
    pub(super) active_unique_ips: usize,
    pub(super) total_octets: u64,
}

#[derive(Serialize)]
pub(super) struct CreateUserResponse {
    pub(super) user: UserInfo,
    pub(super) secret: String,
}

#[derive(Deserialize)]
pub(super) struct CreateUserRequest {
    pub(super) username: String,
    pub(super) secret: Option<String>,
    pub(super) user_ad_tag: Option<String>,
    pub(super) max_tcp_conns: Option<usize>,
    pub(super) expiration_rfc3339: Option<String>,
    pub(super) data_quota_bytes: Option<u64>,
    pub(super) max_unique_ips: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PatchUserRequest {
    pub(super) secret: Option<String>,
    pub(super) user_ad_tag: Option<String>,
    pub(super) max_tcp_conns: Option<usize>,
    pub(super) expiration_rfc3339: Option<String>,
    pub(super) data_quota_bytes: Option<u64>,
    pub(super) max_unique_ips: Option<usize>,
}

#[derive(Default, Deserialize)]
pub(super) struct RotateSecretRequest {
    pub(super) secret: Option<String>,
}

pub(super) fn parse_optional_expiration(
    value: Option<&str>,
) -> Result<Option<DateTime<Utc>>, ApiFailure> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(raw)
        .map_err(|_| ApiFailure::bad_request("expiration_rfc3339 must be valid RFC3339"))?;
    Ok(Some(parsed.with_timezone(&Utc)))
}

pub(super) fn is_valid_user_secret(secret: &str) -> bool {
    secret.len() == 32 && secret.chars().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn is_valid_ad_tag(tag: &str) -> bool {
    tag.len() == 32 && tag.chars().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn is_valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= MAX_USERNAME_LEN
        && user
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

pub(super) fn random_user_secret() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

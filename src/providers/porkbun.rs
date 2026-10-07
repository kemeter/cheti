use async_trait::async_trait;
use std::env;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};

use crate::dns::find_zone;
use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    encode_path, relative_name, validate_acme_value, validate_fqdn, validate_https_base,
    validate_zone, KeyedMutex,
};

const PORKBUN_API_BASE: &str = "https://api.porkbun.com/api/json/v3";
const ENV_API_KEY: &str = "PORKBUN_API_KEY";
const ENV_SECRET_API_KEY: &str = "PORKBUN_SECRET_API_KEY";
/// Porkbun rejects TTLs below the account minimum, which is 600 by default.
const DEFAULT_TTL: u32 = 600;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER: &str = "porkbun";
const MAX_ERROR_MESSAGE: usize = 512;

/// Error code returned when the target domain is not opted in to API access.
const CODE_API_ACCESS_DISABLED: &str = "API_ACCESS_DISABLED";
/// Error code returned by `dns/create` when the exact record already exists.
const CODE_DUPLICATE_RECORD: &str = "DUPLICATE_RECORD";
/// Error code returned by `dns/delete` when the record id is unknown.
const CODE_INVALID_RECORD_ID: &str = "INVALID_RECORD_ID";
/// Error codes meaning the credentials, or their scoping, were refused.
const AUTH_CODES: &[&str] = &[
    "API_KEY_REQUIRED",
    "MISSING_SECRETAPIKEY",
    "INVALID_API_KEYS_001",
    "INVALID_API_KEYS_002",
    "INVALID_USER",
    "IP_NOT_ALLOWED",
    "DOMAIN_NOT_ALLOWED",
];

pub struct PorkbunConfig {
    api_key: SecretString,
    secret_api_key: SecretString,
    api_base: String,
    zone_override: Option<String>,
}

impl PorkbunConfig {
    pub fn new(api_key: impl Into<String>, secret_api_key: impl Into<String>) -> Self {
        Self {
            api_key: SecretString::new(api_key.into().into()),
            secret_api_key: SecretString::new(secret_api_key.into().into()),
            api_base: PORKBUN_API_BASE.to_string(),
            zone_override: None,
        }
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        validate_https_base(&base, PROVIDER)?;
        self.api_base = base.trim_end_matches('/').to_string();
        Ok(self)
    }

    /// Skip the SOA lookup and use `zone` directly. `zone` must be a domain of
    /// the Porkbun account, and the given fqdn must be at-or-below it.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(zone.trim_end_matches('.').to_ascii_lowercase());
        Ok(self)
    }
}

pub struct PorkbunProvider {
    config: PorkbunConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
}

impl PorkbunProvider {
    pub fn new(config: PorkbunConfig) -> Result<Self, DnsError> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(DnsError::Http)?;
        Ok(Self {
            config,
            http,
            locks: KeyedMutex::new(),
        })
    }

    pub fn from_env() -> Result<Self, DnsError> {
        let api_key =
            env::var(ENV_API_KEY).map_err(|_| DnsError::MissingCredentials(ENV_API_KEY.into()))?;
        let secret_api_key = env::var(ENV_SECRET_API_KEY)
            .map_err(|_| DnsError::MissingCredentials(ENV_SECRET_API_KEY.into()))?;
        Self::new(PorkbunConfig::new(api_key, secret_api_key))
    }

    async fn resolve_zone(&self, fqdn: &str) -> Result<String, DnsError> {
        match &self.config.zone_override {
            Some(zone) => Ok(zone.trim_end_matches('.').to_string()),
            None => {
                let zone = find_zone(fqdn).await?;
                validate_zone(&zone)?;
                Ok(zone)
            }
        }
    }

    /// Path of the `retrieveByNameType` endpoint. The apex is addressed by
    /// omitting the subdomain segment.
    fn retrieve_path(zone: &str, subdomain: &str) -> String {
        let mut path = format!("/dns/retrieveByNameType/{}/TXT", encode_path(zone));
        if !subdomain.is_empty() {
            path.push('/');
            path.push_str(&encode_path(subdomain).to_string());
        }
        path
    }

    fn create_path(zone: &str) -> String {
        format!("/dns/create/{}", encode_path(zone))
    }

    fn delete_path(zone: &str, id: &str) -> String {
        format!("/dns/delete/{}/{}", encode_path(zone), encode_path(id))
    }

    /// Sends an authenticated POST. Porkbun carries the credentials in the
    /// JSON body of every call, alongside the endpoint-specific fields.
    async fn post<B: Serialize>(
        &self,
        path: &str,
        zone: &str,
        fields: B,
    ) -> Result<serde_json::Value, PorkbunError> {
        let body = AuthenticatedBody {
            apikey: self.config.api_key.expose_secret(),
            secretapikey: self.config.secret_api_key.expose_secret(),
            fields,
        };
        let response = self
            .http
            .post(format!("{}{path}", self.config.api_base))
            .json(&body)
            .send()
            .await?;
        parse_envelope(path, zone, response).await
    }

    /// Returns the TXT records currently at `subdomain`, with their ids.
    async fn fetch_existing(
        &self,
        zone: &str,
        subdomain: &str,
    ) -> Result<Vec<PorkbunRecord>, DnsError> {
        let path = Self::retrieve_path(zone, subdomain);
        let body = self.post(&path, zone, Empty {}).await?;
        let parsed: PorkbunRecords = serde_json::from_value(body).map_err(|e| {
            DnsError::Api(format!(
                "{PROVIDER} POST {path} returned an invalid body: {e}"
            ))
        })?;
        Ok(parsed
            .records
            .into_iter()
            .filter(|r| r.record_type.eq_ignore_ascii_case("TXT"))
            .collect())
    }

    async fn create_record(
        &self,
        zone: &str,
        subdomain: &str,
        value: &str,
    ) -> Result<(), DnsError> {
        let path = Self::create_path(zone);
        let fields = CreateRecord {
            name: subdomain,
            record_type: "TXT",
            content: value,
            ttl: DEFAULT_TTL,
        };
        let body = match self.post(&path, zone, fields).await {
            Ok(body) => body,
            // Another writer created the same record in the meantime.
            Err(PorkbunError::Code(code, _)) if code == CODE_DUPLICATE_RECORD => {
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        // Porkbun stores the record even when the domain is delegated to
        // nameservers it does not operate, and only says so in `warnings`.
        // Such a record never resolves, so fail now instead of letting the
        // propagation check time out.
        let created: CreatedRecord = serde_json::from_value(body).unwrap_or_default();
        let warnings = created.warnings.into_vec();
        if warnings.is_empty() {
            return Ok(());
        }
        if let Some(id) = created.id {
            // Best effort: the error below matters more than a failed rollback.
            let _ = self.delete_record(zone, &id).await;
        }
        Err(DnsError::Api(format!(
            "{PROVIDER}: record for {zone} was stored but will not resolve: {}",
            truncate(&warnings.join(" "))
        )))
    }

    async fn delete_record(&self, zone: &str, id: &str) -> Result<(), DnsError> {
        let path = Self::delete_path(zone, id);
        match self.post(&path, zone, Empty {}).await {
            Ok(_) => Ok(()),
            // Already removed, which is the state cleanup is after.
            Err(PorkbunError::Code(code, _)) if code == CODE_INVALID_RECORD_ID => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Failure of a Porkbun call, keeping the machine-readable error code so
/// callers can tolerate the ones that mean "already done".
enum PorkbunError {
    Code(String, DnsError),
    Other(DnsError),
}

impl From<PorkbunError> for DnsError {
    fn from(e: PorkbunError) -> Self {
        match e {
            PorkbunError::Code(_, err) => err,
            PorkbunError::Other(err) => err,
        }
    }
}

impl From<reqwest::Error> for PorkbunError {
    fn from(e: reqwest::Error) -> Self {
        PorkbunError::Other(DnsError::Http(e))
    }
}

/// Reads the `{"status": "SUCCESS" | "ERROR", ...}` envelope every Porkbun
/// response carries. An `ERROR` status is a failure even on HTTP 200.
async fn parse_envelope(
    path: &str,
    zone: &str,
    response: reqwest::Response,
) -> Result<serde_json::Value, PorkbunError> {
    let status = response.status();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let raw = response.text().await?;
    let body: Option<serde_json::Value> = serde_json::from_str(&raw).ok();
    let envelope = body
        .as_ref()
        .and_then(|b| serde_json::from_value::<Envelope>(b.clone()).ok());

    if let (true, Some(env), Some(body)) = (status.is_success(), &envelope, &body) {
        if env.status.eq_ignore_ascii_case("SUCCESS") {
            return Ok(body.clone());
        }
    }

    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let hint = match retry_after {
            Some(secs) => format!("retry after {secs}s"),
            None => "retry later".to_string(),
        };
        return Err(PorkbunError::Code(
            "RATE_LIMIT_EXCEEDED".to_string(),
            DnsError::Api(format!(
                "{PROVIDER} POST {path} was rate limited (429), {hint}"
            )),
        ));
    }

    let Some(env) = envelope else {
        return Err(PorkbunError::Other(DnsError::Api(format!(
            "{PROVIDER} POST {path} returned {status}: {}",
            truncate(&raw)
        ))));
    };

    let code = env.code.unwrap_or_default();
    let message = truncate(env.message.as_deref().unwrap_or("no message"));
    let err = if code == CODE_API_ACCESS_DISABLED || is_api_access_message(&message) {
        DnsError::Auth(format!(
            "{PROVIDER}: API access is not enabled for domain {zone}; \
             turn on \"API Access\" for it in the Porkbun domain management page ({message})"
        ))
    } else if AUTH_CODES.contains(&code.as_str()) {
        DnsError::Auth(format!(
            "{PROVIDER} POST {path} refused credentials: {code}: {message}"
        ))
    } else if code.is_empty() {
        DnsError::Api(format!(
            "{PROVIDER} POST {path} returned {status}: {message}"
        ))
    } else {
        DnsError::Api(format!(
            "{PROVIDER} POST {path} returned {status}: {code}: {message}"
        ))
    };
    Err(PorkbunError::Code(code, err))
}

/// Older API versions reported a domain not opted in to API access without
/// a stable code, only through the message text.
fn is_api_access_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("api access") || lower.contains("opted in")
}

fn truncate(raw: &str) -> String {
    if raw.len() <= MAX_ERROR_MESSAGE {
        return raw.to_string();
    }
    let mut cut = MAX_ERROR_MESSAGE;
    while cut > 0 && !raw.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut truncated = raw[..cut].to_string();
    truncated.push_str("…(truncated)");
    truncated
}

/// TXT content may come back quoted. ACME values are base64url, so they are
/// never split into several character strings.
fn unquote(content: &str) -> &str {
    let trimmed = content.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
}

/// Porkbun returns ids as strings, but accept numbers as well.
fn string_or_number<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Id {
        Text(String),
        Number(u64),
    }
    match Id::deserialize(deserializer)? {
        Id::Text(s) => Ok(s),
        Id::Number(n) => Ok(n.to_string()),
    }
}

fn optional_string_or_number<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    string_or_number(deserializer).map(Some)
}

#[derive(Serialize)]
struct AuthenticatedBody<'a, B: Serialize> {
    apikey: &'a str,
    secretapikey: &'a str,
    #[serde(flatten)]
    fields: B,
}

#[derive(Serialize)]
struct Empty {}

#[derive(Serialize)]
struct CreateRecord<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    content: &'a str,
    ttl: u32,
}

#[derive(Deserialize, Default)]
struct CreatedRecord {
    #[serde(default, deserialize_with = "optional_string_or_number")]
    id: Option<String>,
    #[serde(default)]
    warnings: Warnings,
}

/// Documented as a list of strings, but described as a single string in
/// places: accept both.
#[derive(Deserialize, Default)]
#[serde(untagged)]
enum Warnings {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl Warnings {
    fn into_vec(self) -> Vec<String> {
        let all = match self {
            Warnings::None => Vec::new(),
            Warnings::One(w) => vec![w],
            Warnings::Many(ws) => ws,
        };
        all.into_iter().filter(|w| !w.trim().is_empty()).collect()
    }
}

#[derive(Deserialize)]
struct Envelope {
    status: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Deserialize)]
struct PorkbunRecords {
    #[serde(default)]
    records: Vec<PorkbunRecord>,
}

#[derive(Deserialize)]
struct PorkbunRecord {
    #[serde(deserialize_with = "string_or_number")]
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
}

/// Porkbun addresses the apex with an empty subdomain.
fn subdomain_of(fqdn: &str, zone: &str) -> Result<String, DnsError> {
    let rname = relative_name(fqdn, zone)?;
    if rname == "@" {
        return Ok(String::new());
    }
    Ok(rname)
}

#[async_trait]
impl DnsProvider for PorkbunProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        // DNS names are case-insensitive, but the zone suffix is matched bytewise.
        let fqdn = &fqdn.to_ascii_lowercase();
        validate_acme_value(value)?;
        let zone = self.resolve_zone(fqdn).await?;
        let subdomain = subdomain_of(fqdn, &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{subdomain}")).await;
        let existing = self.fetch_existing(&zone, &subdomain).await?;
        if existing.iter().any(|r| unquote(&r.content) == value) {
            return Ok(());
        }
        self.create_record(&zone, &subdomain, value).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        // DNS names are case-insensitive, but the zone suffix is matched bytewise.
        let fqdn = &fqdn.to_ascii_lowercase();
        let zone = self.resolve_zone(fqdn).await?;
        let subdomain = subdomain_of(fqdn, &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{subdomain}")).await;
        let existing = self.fetch_existing(&zone, &subdomain).await?;
        for record in existing.iter().filter(|r| unquote(&r.content) == value) {
            self.delete_record(&zone, &record.id).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_api_base_rejects_non_https() {
        let cfg = PorkbunConfig::new("pk", "sk");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = PorkbunConfig::new("pk", "sk");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn paths_percent_encode_segments() {
        let path = PorkbunProvider::retrieve_path("foo/../bar", "_acme");
        assert!(path.contains("foo%2F..%2Fbar"), "got {path}");
        let path = PorkbunProvider::delete_path("example.com", "1/2");
        assert!(path.ends_with("1%2F2"), "got {path}");
    }

    #[test]
    fn retrieve_path_omits_empty_subdomain() {
        assert_eq!(
            PorkbunProvider::retrieve_path("example.com", ""),
            "/dns/retrieveByNameType/example.com/TXT"
        );
    }

    #[test]
    fn subdomain_of_apex_is_empty() {
        assert_eq!(subdomain_of("example.com", "example.com").unwrap(), "");
        assert_eq!(
            subdomain_of("_acme-challenge.example.com", "example.com").unwrap(),
            "_acme-challenge"
        );
    }

    #[test]
    fn unquote_strips_surrounding_quotes() {
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("abc"), "abc");
    }

    #[test]
    fn detects_legacy_api_access_message() {
        assert!(is_api_access_message(
            "Domain is not opted in to API access."
        ));
        assert!(!is_api_access_message("Invalid domain."));
    }
}

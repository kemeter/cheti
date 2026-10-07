use async_trait::async_trait;
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    api_error, encode_path, relative_name, validate_acme_value, validate_fqdn, validate_https_base,
    validate_zone, KeyedMutex,
};

const INFOMANIAK_API_BASE: &str = "https://api.infomaniak.com";
const ENV_TOKEN: &str = "INFOMANIAK_ACCESS_TOKEN";
/// The API accepts TTLs between 60 and 86400 seconds.
const DEFAULT_TTL: u32 = 300;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER: &str = "infomaniak";
/// Error code returned on `POST /records` when an identical record exists.
const ALREADY_EXISTS: &str = "dns_record_already_exists";
/// Upper bound on pages read from a record listing, so a server that keeps
/// reporting more pages cannot loop us forever. Hitting it is an error: a
/// partial listing could hide the record we are looking for.
const MAX_PAGES: u32 = 100;

pub struct InfomaniakConfig {
    access_token: SecretString,
    api_base: String,
    zone_override: Option<String>,
}

impl InfomaniakConfig {
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            access_token: SecretString::new(access_token.into().into()),
            api_base: INFOMANIAK_API_BASE.to_string(),
            zone_override: None,
        }
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        validate_https_base(&base, PROVIDER)?;
        self.api_base = base.trim_end_matches('/').to_string();
        Ok(self)
    }

    /// Skip the zone lookup and use `zone` directly. The given fqdn must be
    /// at-or-below `zone`, and `zone` must be a zone (or delegated sub-zone)
    /// managed by the account.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(zone.trim_end_matches('.').to_ascii_lowercase());
        Ok(self)
    }
}

pub struct InfomaniakProvider {
    config: InfomaniakConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
    /// Cached `fqdn -> zone` mapping, so `cleanup` does not repeat the walk
    /// done by `present`.
    zone_cache: Mutex<HashMap<String, String>>,
}

impl InfomaniakProvider {
    pub fn new(config: InfomaniakConfig) -> Result<Self, DnsError> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(DnsError::Http)?;
        Ok(Self {
            config,
            http,
            locks: KeyedMutex::new(),
            zone_cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn from_env() -> Result<Self, DnsError> {
        let token =
            env::var(ENV_TOKEN).map_err(|_| DnsError::MissingCredentials(ENV_TOKEN.into()))?;
        Self::new(InfomaniakConfig::new(token))
    }

    fn zone_path(zone: &str) -> String {
        format!("/2/zones/{}", encode_path(zone))
    }

    fn records_path(zone: &str) -> String {
        format!("/2/zones/{}/records", encode_path(zone))
    }

    fn record_path(zone: &str, record_id: u64) -> String {
        format!("/2/zones/{}/records/{record_id}", encode_path(zone))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.api_base)
    }

    /// Finds the zone owning `fqdn`: the configured override, or the longest
    /// suffix of `fqdn` that the API knows as a zone. Delegated sub-zones are
    /// zones of their own, so the walk starts from the fqdn itself.
    async fn resolve_zone(&self, fqdn: &str) -> Result<String, DnsError> {
        if let Some(zone) = &self.config.zone_override {
            return Ok(zone.clone());
        }

        let name = fqdn.trim_end_matches('.').to_ascii_lowercase();
        if let Some(zone) = self.zone_cache.lock().unwrap().get(&name) {
            return Ok(zone.clone());
        }

        let labels: Vec<&str> = name.split('.').collect();
        // A zone has at least two labels, so the bare TLD is never queried.
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            if let Some(zone) = self.fetch_zone(&candidate).await? {
                validate_zone(&zone)?;
                // The fqdn must sit inside the zone the API reported.
                relative_name(&name, &zone)?;
                self.zone_cache
                    .lock()
                    .unwrap()
                    .insert(name.clone(), zone.clone());
                return Ok(zone);
            }
        }
        Err(DnsError::ZoneNotFound(fqdn.to_string()))
    }

    /// Returns the zone's fqdn, or `None` when no zone of the account has
    /// that name.
    async fn fetch_zone(&self, candidate: &str) -> Result<Option<String>, DnsError> {
        let path = Self::zone_path(candidate);
        let response = self
            .http
            .get(self.url(&path))
            .bearer_auth(self.config.access_token.expose_secret())
            .send()
            .await?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(api_error(PROVIDER, "GET", path, status, response).await);
        }

        let body: IkEnvelope<IkZone> = response.json().await?;
        let zone = body.into_data("GET", &path)?;
        Ok(Some(zone.fqdn.trim_end_matches('.').to_ascii_lowercase()))
    }

    /// Returns the TXT records of the zone stored at `rname`, following
    /// pagination.
    async fn list_txt_records(&self, zone: &str, rname: &str) -> Result<Vec<IkRecord>, DnsError> {
        let path = Self::records_path(zone);
        let mut matching = Vec::new();
        let mut page: u32 = 1;
        loop {
            let response = self
                .http
                .get(self.url(&path))
                .query(&[
                    ("filter[types][]", "TXT".to_string()),
                    ("page", page.to_string()),
                ])
                .bearer_auth(self.config.access_token.expose_secret())
                .send()
                .await?;

            let status = response.status();
            if !status.is_success() {
                return Err(api_error(PROVIDER, "GET", path, status, response).await);
            }

            let body: IkEnvelope<Vec<IkRecord>> = response.json().await?;
            let pages = body.pages.unwrap_or(1);
            let records = body.into_data("GET", &path)?;
            matching.extend(
                records
                    .into_iter()
                    .filter(|r| r.record_type.eq_ignore_ascii_case("TXT"))
                    .filter(|r| same_source(&r.source, rname)),
            );

            if page >= pages {
                break;
            }
            if page >= MAX_PAGES {
                return Err(DnsError::Api(format!(
                    "{PROVIDER} GET {path}: TXT listing has {pages} pages, more than the {MAX_PAGES} read"
                )));
            }
            page += 1;
        }
        Ok(matching)
    }

    async fn create_record(&self, zone: &str, rname: &str, value: &str) -> Result<(), DnsError> {
        let path = Self::records_path(zone);
        // The apex is "@" for us but "." for the API.
        let source = if rname == "@" { "." } else { rname };
        let body = IkRecordWrite {
            source,
            record_type: "TXT",
            target: value,
            ttl: DEFAULT_TTL,
        };

        let response = self
            .http
            .post(self.url(&path))
            .bearer_auth(self.config.access_token.expose_secret())
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let raw = response.text().await.unwrap_or_default();
            // Another writer created the same record in the meantime.
            if let Ok(err) = serde_json::from_str::<IkEnvelope<serde_json::Value>>(&raw) {
                if err.error_code() == Some(ALREADY_EXISTS) {
                    return Ok(());
                }
            }
            return Err(DnsError::Api(format!(
                "{PROVIDER} POST {path} returned {status}: {}",
                truncate(&raw)
            )));
        }

        let body: IkEnvelope<serde_json::Value> = response.json().await?;
        body.into_data("POST", &path)?;
        Ok(())
    }

    async fn delete_record(&self, zone: &str, record_id: u64) -> Result<(), DnsError> {
        let path = Self::record_path(zone, record_id);
        let response = self
            .http
            .delete(self.url(&path))
            .bearer_auth(self.config.access_token.expose_secret())
            .send()
            .await?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        if !status.is_success() {
            return Err(api_error(PROVIDER, "DELETE", path, status, response).await);
        }

        let body: IkEnvelope<serde_json::Value> = response.json().await?;
        body.into_data("DELETE", &path)?;
        Ok(())
    }
}

/// Compares a record's relative `source` with our relative name. The apex
/// may be reported as ".", "@" or an empty string.
fn same_source(source: &str, rname: &str) -> bool {
    let source = source.trim_end_matches('.');
    if rname == "@" {
        return source.is_empty() || source == "@";
    }
    source.eq_ignore_ascii_case(rname)
}

/// TXT targets come back quoted (`"value"`). ACME values are base64url, so
/// they are never split into several character strings.
fn unquote(target: &str) -> &str {
    let trimmed = target.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
}

fn truncate(raw: &str) -> String {
    const MAX: usize = 512;
    if raw.len() <= MAX {
        return raw.to_string();
    }
    let mut cut = MAX;
    while cut > 0 && !raw.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…(truncated)", &raw[..cut])
}

/// Every response is wrapped as `{"result": "success", "data": ...}` or
/// `{"result": "error", "error": {"code": ..., "description": ...}}`.
#[derive(Deserialize)]
struct IkEnvelope<T> {
    result: String,
    #[serde(default = "Option::default")]
    data: Option<T>,
    #[serde(default)]
    error: Option<IkError>,
    /// Only present on paginated listings.
    #[serde(default)]
    pages: Option<u32>,
}

impl<T> IkEnvelope<T> {
    fn into_data(self, method: &str, path: &str) -> Result<T, DnsError> {
        if self.result != "success" {
            return Err(DnsError::Api(format!(
                "{PROVIDER} {method} {path}: result {}: {}",
                self.result,
                self.error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no error details".to_string())
            )));
        }
        self.data
            .ok_or_else(|| DnsError::Api(format!("{PROVIDER} {method} {path}: missing data")))
    }

    fn error_code(&self) -> Option<&str> {
        self.error.as_ref().and_then(|e| e.code.as_deref())
    }
}

#[derive(Deserialize)]
struct IkError {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

impl std::fmt::Display for IkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.code.as_deref().unwrap_or("unknown"),
            self.description.as_deref().unwrap_or("")
        )
    }
}

#[derive(Deserialize)]
struct IkZone {
    fqdn: String,
}

#[derive(Deserialize)]
struct IkRecord {
    id: u64,
    #[serde(default)]
    source: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    target: String,
}

#[derive(Serialize)]
struct IkRecordWrite<'a> {
    source: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    target: &'a str,
    ttl: u32,
}

#[async_trait]
impl DnsProvider for InfomaniakProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        validate_acme_value(value)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(&fqdn.to_ascii_lowercase(), &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;
        let existing = self.list_txt_records(&zone, &rname).await?;
        if existing.iter().any(|r| unquote(&r.target) == value) {
            return Ok(());
        }
        self.create_record(&zone, &rname, value).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(&fqdn.to_ascii_lowercase(), &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;
        let existing = self.list_txt_records(&zone, &rname).await?;
        for record in existing {
            if unquote(&record.target) == value {
                self.delete_record(&zone, record.id).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_api_base_rejects_non_https() {
        let cfg = InfomaniakConfig::new("dummy");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = InfomaniakConfig::new("dummy");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn with_zone_rejects_single_label() {
        let cfg = InfomaniakConfig::new("dummy");
        assert!(cfg.with_zone("localhost").is_err());
    }

    #[test]
    fn records_path_percent_encodes_zone() {
        let path = InfomaniakProvider::records_path("foo/../bar");
        assert!(path.contains("foo%2F..%2Fbar"), "got {path}");
        assert!(!path.contains("foo/../bar"), "got {path}");
    }

    #[test]
    fn same_source_handles_apex_and_case() {
        assert!(same_source(".", "@"));
        assert!(same_source("", "@"));
        assert!(same_source("@", "@"));
        assert!(same_source("_ACME-challenge", "_acme-challenge"));
        assert!(!same_source("_acme-challenge.www", "_acme-challenge"));
    }

    #[test]
    fn unquote_strips_surrounding_quotes() {
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("abc"), "abc");
    }
}

use async_trait::async_trait;
use std::env;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    api_error, encode_path, relative_name, validate_acme_value, validate_fqdn, validate_https_base,
    validate_zone, KeyedMutex,
};

const HETZNER_API_BASE: &str = "https://api.hetzner.cloud/v1";
const ENV_TOKEN: &str = "HETZNER_API_TOKEN";
/// TTL given to a TXT RRSet created by `present`. 60s is the lowest value the
/// API accepts. An existing RRSet keeps its own TTL.
const DEFAULT_TTL: u32 = 60;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Record changes are asynchronous actions; they are polled until they settle.
const ACTION_POLL_INTERVAL: Duration = Duration::from_secs(1);
const ACTION_TIMEOUT: Duration = Duration::from_secs(60);
const PROVIDER: &str = "hetzner";

/// Configuration for the Hetzner DNS provider, backed by the zones API of
/// the Hetzner Cloud API.
pub struct HetznerConfig {
    token: SecretString,
    api_base: String,
    zone_override: Option<String>,
}

impl HetznerConfig {
    pub fn new(api_token: impl Into<String>) -> Self {
        Self {
            token: SecretString::new(api_token.into().into()),
            api_base: HETZNER_API_BASE.to_string(),
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
    /// at-or-below `zone`, and `zone` must be a zone of the project.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(zone.trim_end_matches('.').to_ascii_lowercase());
        Ok(self)
    }
}

pub struct HetznerProvider {
    config: HetznerConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
}

impl HetznerProvider {
    pub fn new(config: HetznerConfig) -> Result<Self, DnsError> {
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
        let token =
            env::var(ENV_TOKEN).map_err(|_| DnsError::MissingCredentials(ENV_TOKEN.into()))?;
        Self::new(HetznerConfig::new(token))
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.config.token.expose_secret())
    }

    fn rrset_path(zone: &str, rname: &str) -> String {
        format!(
            "/zones/{}/rrsets/{}/TXT",
            encode_path(zone),
            encode_path(rname)
        )
    }

    fn rrset_url(&self, zone: &str, rname: &str) -> String {
        format!("{}{}", self.config.api_base, Self::rrset_path(zone, rname))
    }

    /// Finds the zone owning `fqdn`. The API only hosts zones for registrable
    /// domains (no delegated subdomains), so candidates are tried from the
    /// shortest suffix up: the first match is the only possible one.
    async fn resolve_zone(&self, fqdn: &str) -> Result<String, DnsError> {
        if let Some(zone) = &self.config.zone_override {
            return Ok(zone.clone());
        }

        let name = fqdn.trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = name.split('.').collect();
        for start in (0..labels.len().saturating_sub(1)).rev() {
            let candidate = labels[start..].join(".");
            if self.zone_exists(&candidate).await? {
                return Ok(candidate);
            }
        }
        Err(DnsError::ZoneNotFound(fqdn.to_string()))
    }

    async fn zone_exists(&self, name: &str) -> Result<bool, DnsError> {
        let response = self
            .http
            .get(format!("{}/zones", self.config.api_base))
            .query(&[("name", name)])
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(check_error("GET", "/zones".into(), status, response).await);
        }

        let body: HetznerZones = response.json().await?;
        Ok(body.zones.iter().any(|z| z.name == name))
    }

    /// Returns the unquoted TXT values of the RRSet, or `None` when it does
    /// not exist.
    async fn fetch_existing(
        &self,
        zone: &str,
        rname: &str,
    ) -> Result<Option<Vec<String>>, DnsError> {
        let response = self
            .http
            .get(self.rrset_url(zone, rname))
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(check_error("GET", Self::rrset_path(zone, rname), status, response).await);
        }

        let body: HetznerRrsetResponse = response.json().await?;
        Ok(Some(
            body.rrset
                .records
                .iter()
                .map(|r| unquote(&r.value))
                .collect(),
        ))
    }

    /// Runs an RRSet action (`add_records` / `remove_records`) for a single
    /// value and waits for it to complete.
    async fn run_records_action(
        &self,
        zone: &str,
        rname: &str,
        action: &str,
        value: &str,
        ttl: Option<u32>,
    ) -> Result<(), DnsError> {
        let path = format!("{}/actions/{action}", Self::rrset_path(zone, rname));
        let body = HetznerRecordsWrite {
            ttl,
            records: vec![HetznerRecord {
                value: format!("\"{value}\""),
            }],
        };

        let response = self
            .http
            .post(format!("{}{path}", self.config.api_base))
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(check_error("POST", path, status, response).await);
        }

        let body: HetznerActionResponse = response.json().await?;
        self.wait_for_action(body.action).await
    }

    async fn wait_for_action(&self, mut action: HetznerAction) -> Result<(), DnsError> {
        let deadline = tokio::time::Instant::now() + ACTION_TIMEOUT;
        loop {
            match action.status.as_str() {
                "success" => {
                    return Ok(());
                }
                "error" => {
                    let detail = match action.error {
                        Some(e) => format!("{}: {}", e.code, e.message),
                        None => "unknown error".to_string(),
                    };
                    return Err(DnsError::Api(format!(
                        "{PROVIDER} action {} ({}) failed: {detail}",
                        action.id, action.command
                    )));
                }
                _ => {}
            }

            if tokio::time::Instant::now() + ACTION_POLL_INTERVAL > deadline {
                return Err(DnsError::Api(format!(
                    "{PROVIDER} action {} ({}) still {} after {}s",
                    action.id,
                    action.command,
                    action.status,
                    ACTION_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(ACTION_POLL_INTERVAL).await;
            action = self.fetch_action(action.id).await?;
        }
    }

    async fn fetch_action(&self, id: u64) -> Result<HetznerAction, DnsError> {
        let path = format!("/zones/actions/{id}");
        let response = self
            .http
            .get(format!("{}{path}", self.config.api_base))
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(check_error("GET", path, status, response).await);
        }

        let body: HetznerActionResponse = response.json().await?;
        Ok(body.action)
    }
}

/// Maps a failed response to a `DnsError`, turning throttling into an explicit
/// message that carries the server-provided reset time.
async fn check_error(
    method: &str,
    path: String,
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> DnsError {
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let reset = response
            .headers()
            .get("ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let hint = match reset {
            Some(ts) => format!("limit resets at unix time {ts}"),
            None => "retry later".to_string(),
        };
        return DnsError::Api(format!(
            "{PROVIDER} {method} {path} was rate limited (429), {hint}"
        ));
    }
    api_error(PROVIDER, method, path, status, response).await
}

/// TXT values are exchanged in presentation format: `"value"`. ACME values
/// are base64url, so they are never split into several character strings.
fn unquote(record: &str) -> String {
    let trimmed = record.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
        .to_string()
}

#[derive(Deserialize)]
struct HetznerZones {
    zones: Vec<HetznerZone>,
}

#[derive(Deserialize)]
struct HetznerZone {
    name: String,
}

#[derive(Deserialize)]
struct HetznerRrsetResponse {
    rrset: HetznerRrset,
}

#[derive(Deserialize)]
struct HetznerRrset {
    records: Vec<HetznerRecord>,
}

#[derive(Deserialize, Serialize)]
struct HetznerRecord {
    value: String,
}

#[derive(Serialize)]
struct HetznerRecordsWrite {
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    records: Vec<HetznerRecord>,
}

#[derive(Deserialize)]
struct HetznerActionResponse {
    action: HetznerAction,
}

#[derive(Deserialize)]
struct HetznerAction {
    id: u64,
    #[serde(default)]
    command: String,
    status: String,
    #[serde(default)]
    error: Option<HetznerActionError>,
}

#[derive(Deserialize)]
struct HetznerActionError {
    code: String,
    message: String,
}

#[async_trait]
impl DnsProvider for HetznerProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        validate_acme_value(value)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(&fqdn.to_ascii_lowercase(), &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;
        let existing = self.fetch_existing(&zone, &rname).await?;
        // `add_records` appends to an existing RRSet, keeping the other values
        // (e.g. a wildcard and its apex sharing `_acme-challenge`). A TTL is
        // only sent when creating the RRSet: the API rejects one that differs
        // from the TTL of an existing RRSet.
        let ttl = match &existing {
            Some(values) => {
                if values.iter().any(|v| v == value) {
                    return Ok(());
                }
                None
            }
            None => Some(DEFAULT_TTL),
        };
        self.run_records_action(&zone, &rname, "add_records", value, ttl)
            .await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(&fqdn.to_ascii_lowercase(), &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;
        let existing = self.fetch_existing(&zone, &rname).await?;
        let present = match existing {
            Some(values) => values.iter().any(|v| v == value),
            None => false,
        };
        if !present {
            return Ok(());
        }
        // Removing the last value deletes the RRSet.
        self.run_records_action(&zone, &rname, "remove_records", value, None)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_api_base_rejects_non_https() {
        let cfg = HetznerConfig::new("dummy");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = HetznerConfig::new("dummy");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn with_zone_rejects_single_label() {
        let cfg = HetznerConfig::new("dummy");
        assert!(cfg.with_zone("localhost").is_err());
    }

    #[test]
    fn rrset_url_percent_encodes_segments() {
        let cfg = HetznerConfig::new("dummy");
        let provider = HetznerProvider::new(cfg).unwrap();
        let url = provider.rrset_url("foo/../bar", "_acme");
        assert!(url.contains("foo%2F..%2Fbar"), "got {url}");
        assert!(!url.contains("foo/../bar"), "got {url}");
    }

    #[test]
    fn unquote_strips_surrounding_quotes() {
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("abc"), "abc");
    }
}

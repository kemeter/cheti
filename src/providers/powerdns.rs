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
    encode_path, relative_name, validate_acme_value, validate_fqdn, validate_https_base,
    validate_zone, KeyedMutex, SendRetrying,
};

const ENV_API_URL: &str = "POWERDNS_API_URL";
const ENV_API_KEY: &str = "POWERDNS_API_KEY";
const ENV_SERVER_ID: &str = "POWERDNS_SERVER_ID";
const API_PATH: &str = "/api/v1";
const DEFAULT_SERVER_ID: &str = "localhost";
const API_KEY_HEADER: &str = "X-API-Key";
/// TTL given to a TXT RRSet created by `present`. An existing RRSet keeps its
/// own TTL.
const DEFAULT_TTL: u32 = 60;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER: &str = "powerdns";
const MAX_ERROR_BODY: usize = 512;

/// Configuration for the PowerDNS provider, backed by the HTTP API of a
/// self-hosted PowerDNS Authoritative server (4.6.2 or later).
pub struct PowerDnsConfig {
    api_key: SecretString,
    api_base: String,
    server_id: String,
    zone_override: Option<String>,
}

impl PowerDnsConfig {
    /// `api_url` is the base URL of the server's webserver (e.g.
    /// `https://pdns.example.com`); the API is reached under `/api/v1`. It
    /// must use https, except for localhost, since the API key travels with
    /// every request.
    pub fn new(api_url: impl Into<String>, api_key: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_url.into();
        validate_https_base(&base, PROVIDER)?;
        let base = base.trim_end_matches('/');
        // Accept a URL that already points at the API root.
        let base = base.strip_suffix(API_PATH).unwrap_or(base);
        Ok(Self {
            api_key: SecretString::new(api_key.into().into()),
            api_base: format!("{base}{API_PATH}"),
            server_id: DEFAULT_SERVER_ID.to_string(),
            zone_override: None,
        })
    }

    /// Server id used in API paths. PowerDNS Authoritative only knows
    /// `localhost` (the default); other ids are for proxies in front of it.
    pub fn with_server_id(mut self, server_id: impl Into<String>) -> Result<Self, DnsError> {
        let server_id = server_id.into();
        if server_id.is_empty() {
            return Err(DnsError::Other(format!("{PROVIDER} server id is empty")));
        }
        self.server_id = server_id;
        Ok(self)
    }

    /// Skip the zone lookup and use `zone` directly. The given fqdn must be
    /// at-or-below `zone`, and `zone` must be a zone (or delegated sub-zone)
    /// served by the server.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(zone.trim_end_matches('.').to_ascii_lowercase());
        Ok(self)
    }
}

/// [`DnsProvider`] backed by the PowerDNS API.
pub struct PowerDnsProvider {
    config: PowerDnsConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
    /// Cached `fqdn -> zone` mapping, so `cleanup` does not repeat the walk
    /// done by `present`.
    zone_cache: Mutex<HashMap<String, String>>,
}

impl PowerDnsProvider {
    /// Builds the provider and its HTTP client.
    pub fn new(config: PowerDnsConfig) -> Result<Self, DnsError> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(DnsError::Http)?;
        Ok(Self {
            config,
            http,
            locks: KeyedMutex::new(PROVIDER),
            zone_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Builds the provider from `POWERDNS_API_URL`, `POWERDNS_API_KEY` and, optionally,
    /// `POWERDNS_SERVER_ID`.
    pub fn from_env() -> Result<Self, DnsError> {
        let api_url =
            env::var(ENV_API_URL).map_err(|_| DnsError::MissingCredentials(ENV_API_URL.into()))?;
        let api_key =
            env::var(ENV_API_KEY).map_err(|_| DnsError::MissingCredentials(ENV_API_KEY.into()))?;
        let mut config = PowerDnsConfig::new(api_url, api_key)?;
        if let Ok(server_id) = env::var(ENV_SERVER_ID) {
            config = config.with_server_id(server_id)?;
        }
        Self::new(config)
    }

    /// Zones are addressed by their canonical name, with the trailing dot.
    fn zone_path(&self, zone: &str) -> String {
        format!(
            "/servers/{}/zones/{}.",
            encode_path(&self.config.server_id),
            encode_path(zone)
        )
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.api_base)
    }

    /// Finds the zone owning `fqdn`: the configured override, or the longest
    /// suffix of `fqdn` that the server knows as a zone. Delegated sub-zones
    /// are zones of their own, so the walk starts from the fqdn itself.
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
                // The fqdn must sit inside the zone the server reported.
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

    /// Returns the zone's name, or `None` when the server has no such zone.
    async fn fetch_zone(&self, candidate: &str) -> Result<Option<String>, DnsError> {
        let path = self.zone_path(candidate);
        let response = self
            .http
            .get(self.url(&path))
            .query(&[("rrsets", "false")])
            .header(API_KEY_HEADER, self.config.api_key.expose_secret())
            .send_retrying()
            .await?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(check_error("GET", path, status, response).await);
        }

        let body: PdnsZone = response.json().await?;
        Ok(Some(body.name.trim_end_matches('.').to_ascii_lowercase()))
    }

    /// Returns the TXT RRSet at `name`, or `None` when it does not exist.
    async fn fetch_rrset(&self, zone: &str, name: &str) -> Result<Option<PdnsRrset>, DnsError> {
        let path = self.zone_path(zone);
        let response = self
            .http
            .get(self.url(&path))
            .query(&[("rrset_name", name), ("rrset_type", "TXT")])
            .header(API_KEY_HEADER, self.config.api_key.expose_secret())
            .send_retrying()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(check_error("GET", path, status, response).await);
        }

        // The filter is applied again here: servers without it return the
        // whole zone.
        let body: PdnsZoneRrsets = response.json().await?;
        Ok(body.rrsets.into_iter().find(|r| {
            r.record_type.eq_ignore_ascii_case("TXT") && r.name.eq_ignore_ascii_case(name)
        }))
    }

    async fn patch_rrset(&self, zone: &str, rrset: PdnsRrsetWrite<'_>) -> Result<(), DnsError> {
        let path = self.zone_path(zone);
        let body = PdnsPatch {
            rrsets: vec![rrset],
        };

        let response = self
            .http
            .patch(self.url(&path))
            .header(API_KEY_HEADER, self.config.api_key.expose_secret())
            .json(&body)
            .send_retrying()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(check_error("PATCH", path, status, response).await);
        }
        Ok(())
    }

    /// Absolute owner name, as the API expects it: lowercase, trailing dot.
    fn owner_name(fqdn: &str) -> String {
        format!("{}.", fqdn.trim_end_matches('.').to_ascii_lowercase())
    }
}

/// Maps a failed response to a `DnsError`. A rejected API key becomes
/// `DnsError::Auth`; otherwise the `{"error": "..."}` message PowerDNS
/// returns (e.g. on 422) is surfaced, falling back to the raw body.
async fn check_error(
    method: &str,
    path: String,
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> DnsError {
    let raw = response.text().await.unwrap_or_default();
    let detail = match serde_json::from_str::<PdnsError>(&raw) {
        Ok(err) => truncate(&err.error),
        Err(_) => truncate(&raw),
    };
    let message = format!("{PROVIDER} {method} {path} returned {status}: {detail}");
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        DnsError::Auth(message)
    } else {
        DnsError::Api(message)
    }
}

fn truncate(raw: &str) -> String {
    if raw.len() <= MAX_ERROR_BODY {
        return raw.to_string();
    }
    let mut cut = MAX_ERROR_BODY;
    while cut > 0 && !raw.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…(truncated)", &raw[..cut])
}

/// TXT contents are exchanged in presentation format: `"value"`. ACME values
/// are base64url, so they are never split into several character strings.
fn unquote(content: &str) -> &str {
    let trimmed = content.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
}

#[derive(Deserialize)]
struct PdnsError {
    error: String,
}

#[derive(Deserialize)]
struct PdnsZone {
    name: String,
}

#[derive(Deserialize)]
struct PdnsZoneRrsets {
    #[serde(default)]
    rrsets: Vec<PdnsRrset>,
}

#[derive(Deserialize)]
struct PdnsRrset {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    ttl: u32,
    records: Vec<PdnsRecord>,
}

#[derive(Deserialize, Serialize, Clone)]
struct PdnsRecord {
    content: String,
    #[serde(default)]
    disabled: bool,
}

#[derive(Serialize)]
struct PdnsPatch<'a> {
    rrsets: Vec<PdnsRrsetWrite<'a>>,
}

#[derive(Serialize)]
struct PdnsRrsetWrite<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    changetype: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<Vec<PdnsRecord>>,
}

#[async_trait]
impl DnsProvider for PowerDnsProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        validate_acme_value(value)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(&fqdn.to_ascii_lowercase(), &zone)?;
        let name = Self::owner_name(fqdn);

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;
        let existing = self.fetch_rrset(&zone, &name).await?;
        // REPLACE overwrites the whole RRSet, so the other values (e.g. a
        // wildcard and its apex sharing `_acme-challenge`) are written back
        // as they are, along with the RRSet's TTL.
        let (ttl, mut records) = match existing {
            Some(rrset) => {
                if rrset.records.iter().any(|r| unquote(&r.content) == value) {
                    return Ok(());
                }
                (rrset.ttl, rrset.records)
            }
            None => (DEFAULT_TTL, Vec::new()),
        };
        records.push(PdnsRecord {
            content: format!("\"{value}\""),
            disabled: false,
        });

        self.patch_rrset(
            &zone,
            PdnsRrsetWrite {
                name: &name,
                record_type: "TXT",
                ttl: Some(ttl),
                changetype: "REPLACE",
                records: Some(records),
            },
        )
        .await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(&fqdn.to_ascii_lowercase(), &zone)?;
        let name = Self::owner_name(fqdn);

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;
        let Some(rrset) = self.fetch_rrset(&zone, &name).await? else {
            return Ok(());
        };
        let before = rrset.records.len();
        let remaining: Vec<PdnsRecord> = rrset
            .records
            .into_iter()
            .filter(|r| unquote(&r.content) != value)
            .collect();
        if remaining.len() == before {
            return Ok(());
        }

        // Removing the last value deletes the RRSet: PowerDNS rejects a
        // REPLACE with no records.
        let write = if remaining.is_empty() {
            PdnsRrsetWrite {
                name: &name,
                record_type: "TXT",
                ttl: None,
                changetype: "DELETE",
                records: None,
            }
        } else {
            PdnsRrsetWrite {
                name: &name,
                record_type: "TXT",
                ttl: Some(rrset.ttl),
                changetype: "REPLACE",
                records: Some(remaining),
            }
        };
        self.patch_rrset(&zone, write).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_non_https() {
        assert!(PowerDnsConfig::new("http://pdns.example.com", "dummy").is_err());
    }

    #[test]
    fn new_accepts_localhost_for_tests() {
        assert!(PowerDnsConfig::new("http://localhost:8081", "dummy").is_ok());
    }

    #[test]
    fn new_appends_api_path_once() {
        let cfg = PowerDnsConfig::new("https://pdns.example.com/", "dummy").unwrap();
        assert_eq!(cfg.api_base, "https://pdns.example.com/api/v1");
        let cfg = PowerDnsConfig::new("https://pdns.example.com/api/v1/", "dummy").unwrap();
        assert_eq!(cfg.api_base, "https://pdns.example.com/api/v1");
    }

    #[test]
    fn with_server_id_rejects_empty() {
        let cfg = PowerDnsConfig::new("https://pdns.example.com", "dummy").unwrap();
        assert!(cfg.with_server_id("").is_err());
    }

    #[test]
    fn with_zone_rejects_single_label() {
        let cfg = PowerDnsConfig::new("https://pdns.example.com", "dummy").unwrap();
        assert!(cfg.with_zone("localhost").is_err());
    }

    #[test]
    fn zone_path_percent_encodes_segments() {
        let cfg = PowerDnsConfig::new("https://pdns.example.com", "dummy")
            .unwrap()
            .with_server_id("a/b")
            .unwrap();
        let provider = PowerDnsProvider::new(cfg).unwrap();
        let path = provider.zone_path("foo/../bar");
        assert_eq!(path, "/servers/a%2Fb/zones/foo%2F..%2Fbar.");
    }

    #[test]
    fn owner_name_is_absolute_and_lowercase() {
        assert_eq!(
            PowerDnsProvider::owner_name("_acme-challenge.Example.com"),
            "_acme-challenge.example.com."
        );
        assert_eq!(
            PowerDnsProvider::owner_name("_acme-challenge.example.com."),
            "_acme-challenge.example.com."
        );
    }

    #[test]
    fn unquote_strips_surrounding_quotes() {
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("abc"), "abc");
    }
}

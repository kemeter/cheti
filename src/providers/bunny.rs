use async_trait::async_trait;
use std::env;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    api_error, relative_name, validate_acme_value, validate_fqdn, validate_https_base,
    validate_zone, KeyedMutex, SendRetrying,
};

const BUNNY_API_BASE: &str = "https://api.bunny.net";
const ENV_API_KEY: &str = "BUNNY_API_KEY";
const ACCESS_KEY_HEADER: &str = "AccessKey";
/// `DnsRecordTypes` value of TXT in the Bunny API.
const RECORD_TYPE_TXT: u8 = 3;
/// The API does not document a TTL floor; 60s is the lowest value known to
/// be accepted for TXT records.
const DEFAULT_TTL: u32 = 60;
/// Largest page size accepted by the zone list endpoint.
const PER_PAGE: u32 = 1000;
/// Upper bound on followed pages, so a misbehaving API cannot loop forever.
const MAX_PAGES: u32 = 50;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ERROR_MESSAGE: usize = 512;
const PROVIDER: &str = "bunny";

/// Configuration for the Bunny DNS provider (bunny.net).
pub struct BunnyConfig {
    api_key: SecretString,
    api_base: String,
    zone_override: Option<String>,
}

impl BunnyConfig {
    /// `api_key` is the account API key, sent in the `AccessKey` header.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: SecretString::new(api_key.into().into()),
            api_base: BUNNY_API_BASE.to_string(),
            zone_override: None,
        }
    }

    /// Overrides the API base URL, e.g. to target a mock server. It must use
    /// `https://` (`http://` is accepted for `localhost` only).
    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        validate_https_base(&base, PROVIDER)?;
        self.api_base = base.trim_end_matches('/').to_string();
        Ok(self)
    }

    /// Skip the longest-suffix search and use the Bunny zone whose domain is
    /// `zone`. The fqdn must be at-or-below it.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(zone.trim_end_matches('.').to_ascii_lowercase());
        Ok(self)
    }
}

/// [`DnsProvider`] backed by the Bunny DNS API.
pub struct BunnyProvider {
    config: BunnyConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
}

/// A Bunny DNS zone, identified by its numeric id.
struct Zone {
    id: i64,
    domain: String,
}

impl BunnyProvider {
    /// Builds the provider and its HTTP client.
    pub fn new(config: BunnyConfig) -> Result<Self, DnsError> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(DnsError::Http)?;
        Ok(Self {
            config,
            http,
            locks: KeyedMutex::new(PROVIDER),
        })
    }

    /// Builds the provider from `BUNNY_API_KEY`.
    pub fn from_env() -> Result<Self, DnsError> {
        let api_key =
            env::var(ENV_API_KEY).map_err(|_| DnsError::MissingCredentials(ENV_API_KEY.into()))?;
        Self::new(BunnyConfig::new(api_key))
    }

    fn zone_path(zone_id: i64) -> String {
        format!("/dnszone/{zone_id}")
    }

    fn records_path(zone_id: i64) -> String {
        format!("/dnszone/{zone_id}/records")
    }

    fn record_item_path(zone_id: i64, record_id: i64) -> String {
        format!("/dnszone/{zone_id}/records/{record_id}")
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.api_base)
    }

    /// Finds the zone owning `fqdn`: the account zone whose domain is the
    /// longest suffix of it, so delegated sub-zones win over their parent.
    /// With `with_zone`, only that exact domain is accepted.
    async fn resolve_zone(&self, fqdn: &str) -> Result<Zone, DnsError> {
        let name = fqdn.trim_end_matches('.');
        if let Some(zone) = &self.config.zone_override {
            return self
                .list_zones(zone)
                .await?
                .into_iter()
                .find(|z| &z.domain == zone)
                .ok_or_else(|| DnsError::ZoneNotFound(zone.clone()));
        }

        // Every candidate zone has at least two labels and ends with the
        // last two labels of the fqdn, so searching for them narrows the
        // listing without missing any candidate.
        let labels: Vec<&str> = name.split('.').collect();
        let search = labels[labels.len().saturating_sub(2)..].join(".");
        self.list_zones(&search)
            .await?
            .into_iter()
            .filter(|z| is_suffix(name, &z.domain))
            .max_by_key(|z| z.domain.len())
            .ok_or_else(|| DnsError::ZoneNotFound(fqdn.to_string()))
    }

    /// Lists the account zones matching `search`, following pagination.
    async fn list_zones(&self, search: &str) -> Result<Vec<Zone>, DnsError> {
        let per_page = PER_PAGE.to_string();
        let mut zones = Vec::new();
        let mut page: u32 = 1;

        loop {
            let page_param = page.to_string();
            let response = self
                .http
                .get(self.url("/dnszone"))
                .query(&[
                    ("search", search),
                    ("perPage", per_page.as_str()),
                    ("page", page_param.as_str()),
                ])
                .header(ACCESS_KEY_HEADER, self.config.api_key.expose_secret())
                .send_retrying()
                .await?;

            let status = response.status();
            if !status.is_success() {
                return Err(check_error("GET", "/dnszone".into(), status, response).await);
            }

            let body: BunnyZoneList = response.json().await?;
            zones.extend(body.items.into_iter().flatten().map(|z| Zone {
                id: z.id,
                domain: z.domain.trim_end_matches('.').to_ascii_lowercase(),
            }));

            if !body.has_more_items {
                break;
            }
            if page >= MAX_PAGES {
                return Err(DnsError::Api(format!(
                    "{PROVIDER} GET /dnszone: more than {MAX_PAGES} pages of zones"
                )));
            }
            page += 1;
        }

        Ok(zones)
    }

    /// Returns the TXT records of the zone named `rname` (relative, `""` for
    /// the apex).
    async fn list_matching_records(
        &self,
        zone: &Zone,
        rname: &str,
    ) -> Result<Vec<BunnyRecord>, DnsError> {
        let path = Self::zone_path(zone.id);
        let response = self
            .http
            .get(self.url(&path))
            .header(ACCESS_KEY_HEADER, self.config.api_key.expose_secret())
            .send_retrying()
            .await?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(DnsError::ZoneNotFound(zone.domain.clone()));
        }
        if !status.is_success() {
            return Err(check_error("GET", path, status, response).await);
        }

        let body: BunnyZone = response.json().await?;
        Ok(body
            .records
            .into_iter()
            .flatten()
            .filter(|r| r.r#type == RECORD_TYPE_TXT && record_name(r).eq_ignore_ascii_case(rname))
            .collect())
    }

    async fn create_record(&self, zone: &Zone, rname: &str, value: &str) -> Result<(), DnsError> {
        let path = Self::records_path(zone.id);
        let body = AddRecordBody {
            r#type: RECORD_TYPE_TXT,
            ttl: DEFAULT_TTL,
            value,
            name: rname,
        };
        let response = self
            .http
            .put(self.url(&path))
            .header(ACCESS_KEY_HEADER, self.config.api_key.expose_secret())
            .json(&body)
            .send_retrying()
            .await?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(DnsError::ZoneNotFound(zone.domain.clone()));
        }
        if !status.is_success() {
            return Err(check_error("PUT", path, status, response).await);
        }
        Ok(())
    }

    async fn delete_record(&self, zone: &Zone, record_id: i64) -> Result<(), DnsError> {
        let path = Self::record_item_path(zone.id, record_id);
        let response = self
            .http
            .delete(self.url(&path))
            .header(ACCESS_KEY_HEADER, self.config.api_key.expose_secret())
            .send_retrying()
            .await?;

        let status = response.status();
        // A 404 means the record is already gone, which is what we want.
        if !status.is_success() && status != reqwest::StatusCode::NOT_FOUND {
            return Err(check_error("DELETE", path, status, response).await);
        }
        Ok(())
    }
}

/// Whether `zone` is `name` itself or one of its parent domains.
fn is_suffix(name: &str, zone: &str) -> bool {
    name.eq_ignore_ascii_case(zone)
        || (name.len() > zone.len()
            && name.as_bytes()[name.len() - zone.len() - 1] == b'.'
            && name[name.len() - zone.len()..].eq_ignore_ascii_case(zone))
}

/// The apex is stored with an empty name; `@` is accepted defensively.
fn record_name(record: &BunnyRecord) -> &str {
    match record.name.as_deref().unwrap_or("") {
        "@" => "",
        name => name,
    }
}

/// TXT values are returned unquoted, but strip quotes defensively in case the
/// value comes back in presentation format.
fn record_value(record: &BunnyRecord) -> &str {
    record
        .value
        .as_deref()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
}

/// Maps a failed response to a `DnsError`: 401 becomes `Auth`, throttling an
/// explicit message, and Bunny's `ErrorKey`/`Message` body is surfaced.
async fn check_error(
    method: &str,
    path: String,
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> DnsError {
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let hint = match retry_after {
            Some(secs) => format!("retry after {secs}s"),
            None => "retry later".to_string(),
        };
        return DnsError::Api(format!(
            "{PROVIDER} {method} {path} was rate limited (429), {hint}"
        ));
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return DnsError::Auth(format!(
            "{PROVIDER} {method} {path} rejected the API key (401)"
        ));
    }

    let is_json = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("json"));
    if !is_json {
        return api_error(PROVIDER, method, path, status, response).await;
    }

    let raw = response.text().await.unwrap_or_default();
    let detail = match serde_json::from_str::<BunnyErrorBody>(&raw) {
        Ok(BunnyErrorBody {
            error_key,
            message: Some(message),
        }) => match error_key {
            Some(key) => format!("{}: {}", truncate(&key), truncate(&message)),
            None => truncate(&message),
        },
        _ => truncate(&raw),
    };
    DnsError::Api(format!(
        "{PROVIDER} {method} {path} returned {status}: {detail}"
    ))
}

fn truncate(text: &str) -> String {
    if text.len() <= MAX_ERROR_MESSAGE {
        return text.to_string();
    }
    let mut cut = MAX_ERROR_MESSAGE;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…(truncated)", &text[..cut])
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyZoneList {
    #[serde(default)]
    items: Option<Vec<BunnyZoneSummary>>,
    #[serde(default)]
    has_more_items: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyZoneSummary {
    id: i64,
    #[serde(default)]
    domain: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyZone {
    #[serde(default)]
    records: Option<Vec<BunnyRecord>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyRecord {
    id: i64,
    r#type: u8,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct AddRecordBody<'a> {
    r#type: u8,
    ttl: u32,
    value: &'a str,
    name: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyErrorBody {
    #[serde(default)]
    error_key: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[async_trait]
impl DnsProvider for BunnyProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        // DNS names are case-insensitive, but the zone suffix is matched bytewise.
        let fqdn = &fqdn.to_ascii_lowercase();
        validate_acme_value(value)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = bunny_name(fqdn, &zone.domain)?;

        let _guard = self.locks.lock(&format!("{}|{rname}", zone.domain)).await;

        let existing = self.list_matching_records(&zone, &rname).await?;
        if existing.iter().any(|rec| record_value(rec) == value) {
            return Ok(());
        }

        self.create_record(&zone, &rname, value).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        // DNS names are case-insensitive, but the zone suffix is matched bytewise.
        let fqdn = &fqdn.to_ascii_lowercase();
        let zone = self.resolve_zone(fqdn).await?;
        let rname = bunny_name(fqdn, &zone.domain)?;

        let _guard = self.locks.lock(&format!("{}|{rname}", zone.domain)).await;

        let existing = self.list_matching_records(&zone, &rname).await?;
        for rec in existing {
            if record_value(&rec) == value {
                self.delete_record(&zone, rec.id).await?;
            }
        }
        Ok(())
    }
}

/// Record name relative to the zone, with the apex as an empty string.
fn bunny_name(fqdn: &str, zone: &str) -> Result<String, DnsError> {
    let rname = relative_name(fqdn, zone)?;
    Ok(if rname == "@" { String::new() } else { rname })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_api_base_rejects_non_https() {
        let cfg = BunnyConfig::new("key");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = BunnyConfig::new("key");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn with_zone_rejects_single_label() {
        let cfg = BunnyConfig::new("key");
        assert!(cfg.with_zone("localhost").is_err());
    }

    #[test]
    fn is_suffix_requires_label_boundary() {
        assert!(is_suffix("_acme-challenge.example.com", "example.com"));
        assert!(is_suffix("example.com", "example.com"));
        assert!(!is_suffix("_acme-challenge.badexample.com", "example.com"));
        assert!(!is_suffix("example.com", "sub.example.com"));
    }

    #[test]
    fn bunny_name_uses_empty_string_for_apex() {
        assert_eq!(bunny_name("example.com", "example.com").unwrap(), "");
        assert_eq!(
            bunny_name("_acme-challenge.example.com", "example.com").unwrap(),
            "_acme-challenge"
        );
    }

    #[test]
    fn record_value_strips_quotes() {
        let quoted = BunnyRecord {
            id: 1,
            r#type: RECORD_TYPE_TXT,
            name: None,
            value: Some("\"abc\"".into()),
        };
        assert_eq!(record_value(&quoted), "abc");
    }
}

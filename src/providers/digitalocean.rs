use async_trait::async_trait;
use std::env;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::dns::find_zone;
use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    api_error, encode_path, relative_name, validate_acme_value, validate_fqdn, validate_https_base,
    validate_zone, KeyedMutex,
};

const DO_API_BASE: &str = "https://api.digitalocean.com/v2";
const ENV_TOKEN: &str = "DIGITALOCEAN_TOKEN";
/// DigitalOcean rejects TTLs below 30 seconds.
const DEFAULT_TTL: u32 = 30;
/// Largest page size accepted by the list endpoints.
const PER_PAGE: u32 = 200;
/// Upper bound on followed pages, so a misbehaving API cannot loop forever.
const MAX_PAGES: u32 = 50;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER: &str = "digitalocean";

pub struct DigitalOceanConfig {
    token: SecretString,
    api_base: String,
    zone_override: Option<String>,
}

impl DigitalOceanConfig {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: SecretString::new(token.into().into()),
            api_base: DO_API_BASE.to_string(),
            zone_override: None,
        }
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        validate_https_base(&base, PROVIDER)?;
        self.api_base = base.trim_end_matches('/').to_string();
        Ok(self)
    }

    /// Skip the SOA lookup and use `zone` directly. `zone` must be a domain
    /// managed by the DigitalOcean account, and the fqdn must be at-or-below it.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(zone.trim_end_matches('.').to_ascii_lowercase());
        Ok(self)
    }
}

pub struct DigitalOceanProvider {
    config: DigitalOceanConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
}

impl DigitalOceanProvider {
    pub fn new(config: DigitalOceanConfig) -> Result<Self, DnsError> {
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
        Self::new(DigitalOceanConfig::new(token))
    }

    async fn resolve_zone(&self, fqdn: &str) -> Result<String, DnsError> {
        match &self.config.zone_override {
            Some(zone) => Ok(zone.clone()),
            None => {
                let zone = find_zone(fqdn).await?;
                validate_zone(&zone)?;
                Ok(zone)
            }
        }
    }

    fn records_url(&self, zone: &str) -> String {
        format!(
            "{}/domains/{}/records",
            self.config.api_base,
            encode_path(zone)
        )
    }

    fn record_item_url(&self, zone: &str, record_id: u64) -> String {
        format!("{}/{record_id}", self.records_url(zone))
    }

    fn records_path(zone: &str) -> String {
        format!("/domains/{}/records", encode_path(zone))
    }

    /// Lists the TXT records named `fqdn`, following pagination. The `name`
    /// filter takes a fully qualified name, unlike the create body.
    async fn list_matching_records(
        &self,
        zone: &str,
        fqdn: &str,
    ) -> Result<Vec<DoRecord>, DnsError> {
        let name = fqdn.trim_end_matches('.');
        let per_page = PER_PAGE.to_string();
        let mut records = Vec::new();
        let mut page: u32 = 1;

        loop {
            let page_param = page.to_string();
            let response = self
                .http
                .get(self.records_url(zone))
                .query(&[
                    ("type", "TXT"),
                    ("name", name),
                    ("per_page", per_page.as_str()),
                    ("page", page_param.as_str()),
                ])
                .bearer_auth(self.config.token.expose_secret())
                .send()
                .await?;

            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(DnsError::ZoneNotFound(zone.to_string()));
            }
            if !status.is_success() {
                return Err(
                    api_error(PROVIDER, "GET", Self::records_path(zone), status, response).await,
                );
            }

            let body: DoRecordList = response.json().await?;
            records.extend(body.domain_records);

            // Only the presence of a next link is trusted: the page is
            // requested against our own base so the token never follows a
            // server-provided URL.
            let has_next = body
                .links
                .and_then(|l| l.pages)
                .and_then(|p| p.next)
                .is_some();
            if !has_next {
                break;
            }
            if page >= MAX_PAGES {
                return Err(DnsError::Api(format!(
                    "{PROVIDER} GET {}: more than {MAX_PAGES} pages of records",
                    Self::records_path(zone)
                )));
            }
            page += 1;
        }

        Ok(records)
    }

    async fn create_record(&self, zone: &str, rname: &str, value: &str) -> Result<(), DnsError> {
        let body = CreateRecordBody {
            r#type: "TXT",
            name: rname,
            data: value,
            ttl: DEFAULT_TTL,
        };
        let response = self
            .http
            .post(self.records_url(zone))
            .bearer_auth(self.config.token.expose_secret())
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(DnsError::ZoneNotFound(zone.to_string()));
        }
        if !status.is_success() {
            return Err(
                api_error(PROVIDER, "POST", Self::records_path(zone), status, response).await,
            );
        }
        Ok(())
    }

    async fn delete_record(&self, zone: &str, record_id: u64) -> Result<(), DnsError> {
        let response = self
            .http
            .delete(self.record_item_url(zone, record_id))
            .bearer_auth(self.config.token.expose_secret())
            .send()
            .await?;

        let status = response.status();
        // A 404 means the record is already gone, which is what we want.
        if !status.is_success() && status != reqwest::StatusCode::NOT_FOUND {
            return Err(api_error(
                PROVIDER,
                "DELETE",
                format!("{}/{record_id}", Self::records_path(zone)),
                status,
                response,
            )
            .await);
        }
        Ok(())
    }
}

/// TXT data is returned unquoted, but strip quotes defensively in case the
/// value comes back in presentation format.
fn record_value(record: &DoRecord) -> &str {
    record.data.trim().trim_matches('"')
}

#[derive(Deserialize)]
struct DoRecordList {
    #[serde(default)]
    domain_records: Vec<DoRecord>,
    #[serde(default)]
    links: Option<DoLinks>,
}

#[derive(Deserialize)]
struct DoLinks {
    #[serde(default)]
    pages: Option<DoPages>,
}

#[derive(Deserialize)]
struct DoPages {
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize)]
struct DoRecord {
    id: u64,
    #[serde(default)]
    data: String,
}

#[derive(Serialize)]
struct CreateRecordBody<'a> {
    r#type: &'a str,
    name: &'a str,
    data: &'a str,
    ttl: u32,
}

#[async_trait]
impl DnsProvider for DigitalOceanProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        // DNS names are case-insensitive, but the zone suffix is matched bytewise.
        let fqdn = &fqdn.to_ascii_lowercase();
        validate_acme_value(value)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(fqdn, &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;

        let existing = self.list_matching_records(&zone, fqdn).await?;
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
        let rname = relative_name(fqdn, &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;

        let existing = self.list_matching_records(&zone, fqdn).await?;
        for rec in existing {
            if record_value(&rec) == value {
                self.delete_record(&zone, rec.id).await?;
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
        let cfg = DigitalOceanConfig::new("token");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = DigitalOceanConfig::new("token");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn with_zone_rejects_single_label() {
        let cfg = DigitalOceanConfig::new("token");
        assert!(cfg.with_zone("localhost").is_err());
    }

    #[test]
    fn records_url_percent_encodes_zone() {
        let cfg = DigitalOceanConfig::new("token");
        let provider = DigitalOceanProvider::new(cfg).unwrap();
        let url = provider.records_url("foo/../bar");
        assert!(url.contains("foo%2F..%2Fbar"), "got {url}");
        assert!(!url.contains("foo/../bar"), "got {url}");
    }

    #[test]
    fn record_value_strips_quotes() {
        let quoted = DoRecord {
            id: 1,
            data: "\"abc\"".into(),
        };
        let raw = DoRecord {
            id: 2,
            data: "abc".into(),
        };
        assert_eq!(record_value(&quoted), "abc");
        assert_eq!(record_value(&raw), "abc");
    }
}

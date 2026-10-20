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
    validate_zone, KeyedMutex, SendRetrying,
};

const GANDI_API_BASE: &str = "https://api.gandi.net/v5";
const ENV_TOKEN: &str = "GANDIV5_PERSONAL_ACCESS_TOKEN";
const DEFAULT_TTL: u32 = 300;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER: &str = "gandi";

/// Configuration for the Gandi provider.
pub struct GandiConfig {
    personal_access_token: SecretString,
    api_base: String,
    zone_override: Option<String>,
}

impl GandiConfig {
    /// Uses a Gandi personal access token with DNS scope on the domains.
    pub fn new(personal_access_token: impl Into<String>) -> Self {
        Self {
            personal_access_token: SecretString::new(personal_access_token.into().into()),
            api_base: GANDI_API_BASE.to_string(),
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

    /// Skip the SOA lookup and use `zone` directly. Useful when the caller
    /// already knows the apex (avoids a DNS round-trip) or in tests that
    /// don't have a real resolver. The given fqdn must be at-or-below `zone`.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(zone.trim_end_matches('.').to_ascii_lowercase());
        Ok(self)
    }
}

/// [`DnsProvider`] backed by the Gandi API.
pub struct GandiProvider {
    config: GandiConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
}

impl GandiProvider {
    /// Builds the provider and its HTTP client.
    pub fn new(config: GandiConfig) -> Result<Self, DnsError> {
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

    /// Builds the provider from `GANDIV5_PERSONAL_ACCESS_TOKEN`.
    pub fn from_env() -> Result<Self, DnsError> {
        let token =
            env::var(ENV_TOKEN).map_err(|_| DnsError::MissingCredentials(ENV_TOKEN.into()))?;
        Self::new(GandiConfig::new(token))
    }

    fn record_url(&self, zone: &str, rname: &str) -> String {
        format!(
            "{}/livedns/domains/{}/records/{}/TXT",
            self.config.api_base,
            encode_path(zone),
            encode_path(rname)
        )
    }

    fn record_path(zone: &str, rname: &str) -> String {
        format!(
            "/livedns/domains/{}/records/{}/TXT",
            encode_path(zone),
            encode_path(rname)
        )
    }

    async fn fetch_existing(&self, zone: &str, rname: &str) -> Result<Vec<String>, DnsError> {
        let url = self.record_url(zone, rname);
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.config.personal_access_token.expose_secret())
            .send_retrying()
            .await?;

        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(Vec::new());
        }
        if !status.is_success() {
            return Err(api_error(
                PROVIDER,
                "GET",
                Self::record_path(zone, rname),
                status,
                response,
            )
            .await);
        }

        let body: TxtRecordBody = response.json().await?;
        Ok(body.rrset_values)
    }

    async fn put_values(&self, zone: &str, rname: &str, values: &[String]) -> Result<(), DnsError> {
        let url = self.record_url(zone, rname);
        let body = TxtRecordBody {
            rrset_ttl: DEFAULT_TTL,
            rrset_values: values.to_vec(),
        };

        let response = self
            .http
            .put(&url)
            .bearer_auth(self.config.personal_access_token.expose_secret())
            .json(&body)
            .send_retrying()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(api_error(
                PROVIDER,
                "PUT",
                Self::record_path(zone, rname),
                status,
                response,
            )
            .await);
        }
        Ok(())
    }

    async fn delete_record(&self, zone: &str, rname: &str) -> Result<(), DnsError> {
        let url = self.record_url(zone, rname);
        let response = self
            .http
            .delete(&url)
            .bearer_auth(self.config.personal_access_token.expose_secret())
            .send_retrying()
            .await?;

        let status = response.status();
        if !status.is_success() && status.as_u16() != 404 {
            return Err(api_error(
                PROVIDER,
                "DELETE",
                Self::record_path(zone, rname),
                status,
                response,
            )
            .await);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct TxtRecordBody {
    rrset_ttl: u32,
    rrset_values: Vec<String>,
}

impl GandiProvider {
    async fn resolve_zone(&self, fqdn: &str) -> Result<String, DnsError> {
        match &self.config.zone_override {
            Some(z) => Ok(z.clone()),
            None => {
                let zone = find_zone(fqdn).await?;
                validate_fqdn(&zone)?;
                Ok(zone)
            }
        }
    }
}

#[async_trait]
impl DnsProvider for GandiProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        // DNS names are case-insensitive; compare and send them lowercased.
        let fqdn = fqdn.to_ascii_lowercase();
        let fqdn = fqdn.as_str();
        validate_acme_value(value)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(fqdn, &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;
        let mut values = self.fetch_existing(&zone, &rname).await?;
        if values.iter().any(|v| unquote(v) == value) {
            return Ok(());
        }
        // Other values are written back exactly as the API returned them.
        values.push(format!("\"{value}\""));
        self.put_values(&zone, &rname, &values).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        // DNS names are case-insensitive; compare and send them lowercased.
        let fqdn = fqdn.to_ascii_lowercase();
        let fqdn = fqdn.as_str();
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(fqdn, &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;
        let values = self.fetch_existing(&zone, &rname).await?;
        let count = values.len();
        let remaining: Vec<String> = values.into_iter().filter(|v| unquote(v) != value).collect();

        if remaining.len() == count {
            return Ok(());
        }
        if remaining.is_empty() {
            self.delete_record(&zone, &rname).await
        } else {
            self.put_values(&zone, &rname, &remaining).await
        }
    }
}

/// TXT values are exchanged in presentation format (`"value"`), though an
/// unquoted value written by another client may come back as is. ACME values
/// are base64url, so they are never split into several character strings.
fn unquote(value: &str) -> &str {
    let trimmed = value.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquote_strips_surrounding_quotes() {
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("abc"), "abc");
    }

    #[test]
    fn with_api_base_rejects_non_https() {
        let cfg = GandiConfig::new("dummy");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = GandiConfig::new("dummy");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn with_api_base_strips_trailing_slash() {
        let cfg = GandiConfig::new("dummy")
            .with_api_base("https://api.example.com/v1/")
            .unwrap();
        assert_eq!(cfg.api_base, "https://api.example.com/v1");
    }

    #[test]
    fn record_url_percent_encodes_segments() {
        let cfg = GandiConfig::new("dummy");
        let provider = GandiProvider::new(cfg).unwrap();
        let url = provider.record_url("foo/../bar", "_acme");
        assert!(url.contains("foo%2F..%2Fbar"), "got {url}");
        assert!(!url.contains("foo/../bar"), "got {url}");
    }
}

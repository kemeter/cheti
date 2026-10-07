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

const DESEC_API_BASE: &str = "https://desec.io/api/v1";
const ENV_TOKEN: &str = "DESEC_TOKEN";
/// deSEC rejects TTLs below the domain's `minimum_ttl`, which is 3600 for
/// most accounts. Used as a floor when the domain does not report a higher one.
const DEFAULT_TTL: u32 = 3600;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER: &str = "desec";

pub struct DesecConfig {
    token: SecretString,
    api_base: String,
    zone_override: Option<String>,
}

impl DesecConfig {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: SecretString::new(token.into().into()),
            api_base: DESEC_API_BASE.to_string(),
            zone_override: None,
        }
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        validate_https_base(&base, PROVIDER)?;
        self.api_base = base.trim_end_matches('/').to_string();
        Ok(self)
    }

    /// Skip the `owns_qname` lookup and use `zone` directly. The given fqdn
    /// must be at-or-below `zone`, and `zone` must be a domain of the account.
    /// The domain is still read to honour its `minimum_ttl`.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(zone);
        Ok(self)
    }
}

pub struct DesecProvider {
    config: DesecConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
}

/// The zone owning an fqdn, with the TTL to use for records written into it.
struct ResolvedZone {
    name: String,
    ttl: u32,
}

impl DesecProvider {
    pub fn new(config: DesecConfig) -> Result<Self, DnsError> {
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
        Self::new(DesecConfig::new(token))
    }

    fn auth_header(&self) -> String {
        format!("Token {}", self.config.token.expose_secret())
    }

    fn rrsets_url(&self, zone: &str) -> String {
        format!(
            "{}/domains/{}/rrsets/",
            self.config.api_base,
            encode_path(zone)
        )
    }

    fn rrset_url(&self, zone: &str, rname: &str) -> String {
        format!(
            "{}/domains/{}/rrsets/{}/TXT/",
            self.config.api_base,
            encode_path(zone),
            encode_path(rname)
        )
    }

    fn rrset_path(zone: &str, rname: &str) -> String {
        format!(
            "/domains/{}/rrsets/{}/TXT/",
            encode_path(zone),
            encode_path(rname)
        )
    }

    async fn resolve_zone(&self, fqdn: &str) -> Result<ResolvedZone, DnsError> {
        if let Some(zone) = &self.config.zone_override {
            return self.fetch_domain(zone).await;
        }

        let qname = fqdn.trim_end_matches('.');
        let url = format!("{}/domains/", self.config.api_base);
        let response = self
            .http
            .get(&url)
            .query(&[("owns_qname", qname)])
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(check_error("GET", "/domains/".into(), status, response).await);
        }

        let domains: Vec<DesecDomain> = response.json().await?;
        let domain = domains
            .into_iter()
            .next()
            .ok_or_else(|| DnsError::ZoneNotFound(fqdn.to_string()))?;
        validate_zone(&domain.name)?;
        Ok(domain.into_resolved())
    }

    /// Reads a known domain, for its `minimum_ttl`: a write below it is
    /// rejected by deSEC.
    async fn fetch_domain(&self, zone: &str) -> Result<ResolvedZone, DnsError> {
        let path = format!("/domains/{}/", encode_path(zone));
        let response = self
            .http
            .get(format!("{}{path}", self.config.api_base))
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(DnsError::ZoneNotFound(zone.to_string()));
        }
        if !status.is_success() {
            return Err(check_error("GET", path, status, response).await);
        }

        let domain: DesecDomain = response.json().await?;
        Ok(domain.into_resolved())
    }

    /// Returns the unquoted TXT values currently in the RRset.
    async fn fetch_existing(&self, zone: &str, rname: &str) -> Result<Vec<String>, DnsError> {
        let response = self
            .http
            .get(self.rrset_url(zone, rname))
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;

        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(Vec::new());
        }
        if !status.is_success() {
            return Err(check_error("GET", Self::rrset_path(zone, rname), status, response).await);
        }

        let body: DesecRrset = response.json().await?;
        Ok(body.records.iter().map(|r| unquote(r)).collect())
    }

    /// Replaces the RRset with `values` through a bulk PATCH, which creates
    /// the RRset when missing and deletes it when `values` is empty.
    async fn write_values(
        &self,
        zone: &str,
        rname: &str,
        ttl: u32,
        values: &[String],
    ) -> Result<(), DnsError> {
        // The apex is addressed as "@" in URLs but as an empty subname in bodies.
        let subname = if rname == "@" { "" } else { rname };
        let body = [DesecRrsetWrite {
            subname: subname.to_string(),
            rrset_type: "TXT",
            ttl,
            records: values.iter().map(|v| format!("\"{v}\"")).collect(),
        }];

        let response = self
            .http
            .patch(self.rrsets_url(zone))
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let path = format!("/domains/{}/rrsets/", encode_path(zone));
            return Err(check_error("PATCH", path, status, response).await);
        }
        Ok(())
    }
}

/// Maps a failed response to a `DnsError`, turning throttling into an explicit
/// message that carries the server-provided `Retry-After` delay.
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
    api_error(PROVIDER, method, path, status, response).await
}

/// TXT records come back in presentation format: `"value"`. ACME values are
/// base64url, so they are never split into several character strings.
fn unquote(record: &str) -> String {
    let trimmed = record.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
        .to_string()
}

#[derive(Deserialize)]
struct DesecDomain {
    name: String,
    #[serde(default)]
    minimum_ttl: Option<u32>,
}

impl DesecDomain {
    fn into_resolved(self) -> ResolvedZone {
        ResolvedZone {
            ttl: self.minimum_ttl.unwrap_or(DEFAULT_TTL).max(DEFAULT_TTL),
            name: self.name,
        }
    }
}

#[derive(Deserialize)]
struct DesecRrset {
    records: Vec<String>,
}

#[derive(Serialize)]
struct DesecRrsetWrite {
    subname: String,
    #[serde(rename = "type")]
    rrset_type: &'static str,
    ttl: u32,
    records: Vec<String>,
}

#[async_trait]
impl DnsProvider for DesecProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        validate_acme_value(value)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(fqdn, &zone.name)?;

        let _guard = self.locks.lock(&format!("{}|{rname}", zone.name)).await;
        let mut values = self.fetch_existing(&zone.name, &rname).await?;
        let owned_value = value.to_string();
        if values.contains(&owned_value) {
            return Ok(());
        }
        values.push(owned_value);
        self.write_values(&zone.name, &rname, zone.ttl, &values)
            .await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone = self.resolve_zone(fqdn).await?;
        let rname = relative_name(fqdn, &zone.name)?;

        let _guard = self.locks.lock(&format!("{}|{rname}", zone.name)).await;
        let values = self.fetch_existing(&zone.name, &rname).await?;
        if !values.iter().any(|v| v == value) {
            return Ok(());
        }
        let remaining: Vec<String> = values.into_iter().filter(|v| v != value).collect();
        // An empty `records` list deletes the RRset.
        self.write_values(&zone.name, &rname, zone.ttl, &remaining)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_api_base_rejects_non_https() {
        let cfg = DesecConfig::new("dummy");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = DesecConfig::new("dummy");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn rrset_url_percent_encodes_segments() {
        let cfg = DesecConfig::new("dummy");
        let provider = DesecProvider::new(cfg).unwrap();
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

use std::env;
use std::time::Duration;

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::dns::find_zone;
use crate::error::DnsError;
use crate::provider::DnsProvider;

const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

const GANDI_API_BASE: &str = "https://api.gandi.net/v5";
const ENV_TOKEN: &str = "GANDIV5_PERSONAL_ACCESS_TOKEN";
const DEFAULT_TTL: u32 = 300;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ERROR_BODY: usize = 512;

pub struct GandiConfig {
    personal_access_token: SecretString,
    api_base: String,
}

impl GandiConfig {
    pub fn new(personal_access_token: impl Into<String>) -> Self {
        Self {
            personal_access_token: SecretString::new(personal_access_token.into().into()),
            api_base: GANDI_API_BASE.to_string(),
        }
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        let parsed = Url::parse(&base)
            .map_err(|_| DnsError::Other(format!("gandi api_base is not a valid URL: {base}")))?;
        let scheme_ok = parsed.scheme() == "https"
            || (parsed.scheme() == "http"
                && matches!(
                    parsed.host_str(),
                    Some("localhost") | Some("127.0.0.1") | Some("::1")
                ));
        if !scheme_ok {
            return Err(DnsError::Other(format!(
                "gandi api_base must use https:// (got {base})"
            )));
        }
        self.api_base = base;
        Ok(self)
    }
}

pub struct GandiProvider {
    config: GandiConfig,
    http: reqwest::Client,
}

impl GandiProvider {
    pub fn new(config: GandiConfig) -> Result<Self, DnsError> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(DnsError::Http)?;
        Ok(Self { config, http })
    }

    pub fn from_env() -> Result<Self, DnsError> {
        let token =
            env::var(ENV_TOKEN).map_err(|_| DnsError::MissingCredentials(ENV_TOKEN.into()))?;
        Self::new(GandiConfig::new(token))
    }

    fn record_url(&self, zone: &str, rname: &str) -> String {
        let zone_enc = utf8_percent_encode(zone, PATH_SEGMENT);
        let rname_enc = utf8_percent_encode(rname, PATH_SEGMENT);
        format!(
            "{}/livedns/domains/{}/records/{}/TXT",
            self.config.api_base, zone_enc, rname_enc
        )
    }

    fn record_path(zone: &str, rname: &str) -> String {
        let zone_enc = utf8_percent_encode(zone, PATH_SEGMENT);
        let rname_enc = utf8_percent_encode(rname, PATH_SEGMENT);
        format!("/livedns/domains/{zone_enc}/records/{rname_enc}/TXT")
    }

    async fn fetch_existing(&self, zone: &str, rname: &str) -> Result<Vec<String>, DnsError> {
        let url = self.record_url(zone, rname);
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.config.personal_access_token.expose_secret())
            .send()
            .await?;

        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(Vec::new());
        }
        if !status.is_success() {
            return Err(api_error("GET", Self::record_path(zone, rname), status, response).await);
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
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(api_error("PUT", Self::record_path(zone, rname), status, response).await);
        }
        Ok(())
    }

    async fn delete_record(&self, zone: &str, rname: &str) -> Result<(), DnsError> {
        let url = self.record_url(zone, rname);
        let response = self
            .http
            .delete(&url)
            .bearer_auth(self.config.personal_access_token.expose_secret())
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() && status.as_u16() != 404 {
            return Err(
                api_error("DELETE", Self::record_path(zone, rname), status, response).await,
            );
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct TxtRecordBody {
    rrset_ttl: u32,
    rrset_values: Vec<String>,
}

async fn api_error(
    method: &str,
    path: String,
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> DnsError {
    let raw = response.text().await.unwrap_or_default();
    let text = if raw.len() > MAX_ERROR_BODY {
        let mut cut = MAX_ERROR_BODY;
        while cut > 0 && !raw.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut truncated = raw[..cut].to_string();
        truncated.push_str("…(truncated)");
        truncated
    } else {
        raw
    };
    DnsError::Api(format!("gandi {method} {path} returned {status}: {text}"))
}

fn validate_fqdn(fqdn: &str) -> Result<(), DnsError> {
    let trimmed = fqdn.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(DnsError::Other(format!("invalid fqdn length: {fqdn}")));
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::Other(format!("invalid label in {fqdn}")));
        }
        if label.contains('\0') {
            return Err(DnsError::Other("fqdn contains null byte".into()));
        }
    }
    Ok(())
}

fn relative_name(fqdn: &str, zone: &str) -> String {
    let fqdn = fqdn.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if fqdn == zone {
        return "@".to_string();
    }
    let suffix = format!(".{zone}");
    fqdn.strip_suffix(&suffix).unwrap_or(fqdn).to_string()
}

impl DnsProvider for GandiProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone = find_zone(fqdn).await?;
        let rname = relative_name(fqdn, &zone);

        let mut values = self.fetch_existing(&zone, &rname).await?;
        let owned_value = value.to_string();
        if !values.contains(&owned_value) {
            values.push(owned_value);
        }
        self.put_values(&zone, &rname, &values).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone = find_zone(fqdn).await?;
        let rname = relative_name(fqdn, &zone);

        let values = self.fetch_existing(&zone, &rname).await?;
        let remaining: Vec<String> = values.into_iter().filter(|v| v != value).collect();

        if remaining.is_empty() {
            self.delete_record(&zone, &rname).await
        } else {
            self.put_values(&zone, &rname, &remaining).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_name_strips_zone_suffix() {
        assert_eq!(
            relative_name("_acme-challenge.kemeter.app", "kemeter.app"),
            "_acme-challenge"
        );
    }

    #[test]
    fn relative_name_handles_nested_subdomain() {
        assert_eq!(
            relative_name("_acme-challenge.api.kemeter.app", "kemeter.app"),
            "_acme-challenge.api"
        );
    }

    #[test]
    fn relative_name_returns_at_for_apex() {
        assert_eq!(relative_name("kemeter.app", "kemeter.app"), "@");
    }

    #[test]
    fn relative_name_ignores_trailing_dot() {
        assert_eq!(
            relative_name("_acme-challenge.kemeter.app.", "kemeter.app."),
            "_acme-challenge"
        );
    }

    #[test]
    fn validate_fqdn_accepts_normal() {
        assert!(validate_fqdn("_acme-challenge.kemeter.app").is_ok());
        assert!(validate_fqdn("kemeter.app.").is_ok());
    }

    #[test]
    fn validate_fqdn_rejects_empty() {
        assert!(validate_fqdn("").is_err());
        assert!(validate_fqdn(".").is_err());
    }

    #[test]
    fn validate_fqdn_rejects_double_dot() {
        assert!(validate_fqdn("foo..bar.com").is_err());
    }

    #[test]
    fn validate_fqdn_rejects_oversize_label() {
        let long = "a".repeat(64);
        let fqdn = format!("{long}.com");
        assert!(validate_fqdn(&fqdn).is_err());
    }

    #[test]
    fn validate_fqdn_rejects_null_byte() {
        assert!(validate_fqdn("foo\0.bar.com").is_err());
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
    fn with_api_base_rejects_localhost_lookalike() {
        let cfg = GandiConfig::new("dummy");
        assert!(cfg.with_api_base("http://localhost.evil.com").is_err());
    }

    #[test]
    fn with_api_base_rejects_userinfo_smuggling() {
        let cfg = GandiConfig::new("dummy");
        assert!(cfg.with_api_base("http://localhost@attacker.com").is_err());
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

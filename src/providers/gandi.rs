use std::env;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::dns::find_zone;
use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    api_error, encode_path, relative_name, validate_fqdn, validate_https_base,
};

const GANDI_API_BASE: &str = "https://api.gandi.net/v5";
const ENV_TOKEN: &str = "GANDIV5_PERSONAL_ACCESS_TOKEN";
const DEFAULT_TTL: u32 = 300;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const PROVIDER: &str = "gandi";

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
        validate_https_base(&base, PROVIDER)?;
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
            .send()
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
            .send()
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
            .send()
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
    fn record_url_percent_encodes_segments() {
        let cfg = GandiConfig::new("dummy");
        let provider = GandiProvider::new(cfg).unwrap();
        let url = provider.record_url("foo/../bar", "_acme");
        assert!(url.contains("foo%2F..%2Fbar"), "got {url}");
        assert!(!url.contains("foo/../bar"), "got {url}");
    }
}

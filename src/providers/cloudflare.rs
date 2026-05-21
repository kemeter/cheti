use std::env;
use std::sync::Mutex;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::dns::find_zone;
use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    api_error, encode_path, validate_acme_value, validate_fqdn, validate_https_base, validate_zone,
    KeyedMutex,
};

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const ENV_TOKEN: &str = "CLOUDFLARE_API_TOKEN";
const DEFAULT_TTL: u32 = 60;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER: &str = "cloudflare";

pub struct CloudflareConfig {
    api_token: SecretString,
    api_base: String,
    zone_override: Option<ZoneOverride>,
}

#[derive(Clone)]
struct ZoneOverride {
    name: String,
    id: Option<String>,
}

impl CloudflareConfig {
    pub fn new(api_token: impl Into<String>) -> Self {
        Self {
            api_token: SecretString::new(api_token.into().into()),
            api_base: CF_API_BASE.to_string(),
            zone_override: None,
        }
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        validate_https_base(&base, PROVIDER)?;
        self.api_base = base;
        Ok(self)
    }

    /// Override the zone name. The zone id will still be looked up via
    /// `GET /zones?name=` on first use (and cached).
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(ZoneOverride {
            name: zone,
            id: None,
        });
        Ok(self)
    }

    /// Override both zone name and id, skipping all Cloudflare zone lookups.
    /// Useful when the caller already has the id (and avoids one round-trip).
    pub fn with_zone_id(
        mut self,
        zone: impl Into<String>,
        zone_id: impl Into<String>,
    ) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(ZoneOverride {
            name: zone,
            id: Some(zone_id.into()),
        });
        Ok(self)
    }
}

pub struct CloudflareProvider {
    config: CloudflareConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
    /// Cached `name -> id` mapping. Populated on first lookup so subsequent
    /// `present`/`cleanup` calls don't refetch.
    zone_id_cache: Mutex<Option<(String, String)>>,
}

impl CloudflareProvider {
    pub fn new(config: CloudflareConfig) -> Result<Self, DnsError> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(DnsError::Http)?;
        Ok(Self {
            config,
            http,
            locks: KeyedMutex::new(),
            zone_id_cache: Mutex::new(None),
        })
    }

    pub fn from_env() -> Result<Self, DnsError> {
        let token =
            env::var(ENV_TOKEN).map_err(|_| DnsError::MissingCredentials(ENV_TOKEN.into()))?;
        Self::new(CloudflareConfig::new(token))
    }

    async fn resolve_zone_name(&self, fqdn: &str) -> Result<String, DnsError> {
        match &self.config.zone_override {
            Some(o) => Ok(o.name.clone()),
            None => {
                let zone = find_zone(fqdn).await?;
                validate_fqdn(&zone)?;
                Ok(zone)
            }
        }
    }

    async fn resolve_zone_id(&self, zone_name: &str) -> Result<String, DnsError> {
        if let Some(override_) = &self.config.zone_override {
            if let Some(id) = &override_.id {
                return Ok(id.clone());
            }
        }

        if let Some((cached_name, cached_id)) = self.zone_id_cache.lock().unwrap().clone() {
            if cached_name == zone_name {
                return Ok(cached_id);
            }
        }

        let url = format!(
            "{}/zones?name={}",
            self.config.api_base,
            encode_path(zone_name)
        );
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.config.api_token.expose_secret())
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(api_error(PROVIDER, "GET", "/zones".into(), status, response).await);
        }
        let body: CfEnvelope<Vec<CfZone>> = response.json().await?;
        let zones = body.into_result(&format!("GET /zones?name={zone_name}"))?;
        let zone = zones
            .into_iter()
            .find(|z| z.name == zone_name)
            .ok_or_else(|| DnsError::ZoneNotFound(zone_name.to_string()))?;

        *self.zone_id_cache.lock().unwrap() = Some((zone_name.to_string(), zone.id.clone()));
        Ok(zone.id)
    }

    fn records_url(&self, zone_id: &str) -> String {
        format!(
            "{}/zones/{}/dns_records",
            self.config.api_base,
            encode_path(zone_id)
        )
    }

    fn record_item_url(&self, zone_id: &str, record_id: &str) -> String {
        format!(
            "{}/zones/{}/dns_records/{}",
            self.config.api_base,
            encode_path(zone_id),
            encode_path(record_id)
        )
    }

    fn records_path(zone_id: &str) -> String {
        format!("/zones/{zone_id}/dns_records")
    }

    async fn list_matching_records(
        &self,
        zone_id: &str,
        fqdn: &str,
    ) -> Result<Vec<CfDnsRecord>, DnsError> {
        let url = format!(
            "{}?type=TXT&name={}",
            self.records_url(zone_id),
            encode_path(fqdn.trim_end_matches('.'))
        );
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.config.api_token.expose_secret())
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(api_error(
                PROVIDER,
                "GET",
                Self::records_path(zone_id),
                status,
                response,
            )
            .await);
        }
        let body: CfEnvelope<Vec<CfDnsRecord>> = response.json().await?;
        body.into_result(&format!("GET {}", Self::records_path(zone_id)))
    }

    async fn create_record(&self, zone_id: &str, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let url = self.records_url(zone_id);
        // Cloudflare expects TXT content wrapped in double quotes. Sending
        // the raw value works but CF rewrites it, which causes our read-side
        // equality check (after stripping quotes) to mismatch in edge cases.
        let quoted = format!("\"{value}\"");
        let body = CreateRecordBody {
            r#type: "TXT",
            name: fqdn.trim_end_matches('.'),
            content: &quoted,
            ttl: DEFAULT_TTL,
        };
        let response = self
            .http
            .post(&url)
            .bearer_auth(self.config.api_token.expose_secret())
            .json(&body)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(api_error(
                PROVIDER,
                "POST",
                Self::records_path(zone_id),
                status,
                response,
            )
            .await);
        }
        let env: CfEnvelope<CfDnsRecord> = response.json().await?;
        env.into_result(&format!("POST {}", Self::records_path(zone_id)))?;
        Ok(())
    }

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<(), DnsError> {
        let url = self.record_item_url(zone_id, record_id);
        let response = self
            .http
            .delete(&url)
            .bearer_auth(self.config.api_token.expose_secret())
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() && status.as_u16() != 404 {
            return Err(api_error(
                PROVIDER,
                "DELETE",
                Self::records_path(zone_id),
                status,
                response,
            )
            .await);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct CfEnvelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    // `null` on error responses, so it must be optional.
    #[serde(default = "Option::default")]
    result: Option<T>,
}

impl<T> CfEnvelope<T> {
    fn into_result(self, op_label: &str) -> Result<T, DnsError> {
        if !self.success {
            return Err(DnsError::Api(format!(
                "cloudflare {op_label}: {:?}",
                self.errors
            )));
        }
        self.result
            .ok_or_else(|| DnsError::Api(format!("cloudflare {op_label}: missing result")))
    }
}

#[derive(Deserialize, Debug)]
struct CfError {
    #[allow(dead_code)]
    code: i64,
    #[allow(dead_code)]
    message: String,
}

#[derive(Deserialize)]
struct CfZone {
    id: String,
    name: String,
}

#[derive(Deserialize, Clone)]
struct CfDnsRecord {
    id: String,
    content: String,
}

#[derive(Serialize)]
struct CreateRecordBody<'a> {
    r#type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

impl DnsProvider for CloudflareProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        validate_acme_value(value)?;
        let zone_name = self.resolve_zone_name(fqdn).await?;
        let zone_id = self.resolve_zone_id(&zone_name).await?;

        let _guard = self.locks.lock(&format!("{zone_id}|{fqdn}")).await;

        let existing = self.list_matching_records(&zone_id, fqdn).await?;
        // Cloudflare wraps multi-line TXT values in extra quotes; strip them
        // before comparing to our base64url ACME value.
        for rec in &existing {
            if rec.content.trim_matches('"') == value {
                return Ok(());
            }
        }

        self.create_record(&zone_id, fqdn, value).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone_name = self.resolve_zone_name(fqdn).await?;
        let zone_id = self.resolve_zone_id(&zone_name).await?;

        let _guard = self.locks.lock(&format!("{zone_id}|{fqdn}")).await;

        let existing = self.list_matching_records(&zone_id, fqdn).await?;
        for rec in existing {
            if rec.content.trim_matches('"') == value {
                self.delete_record(&zone_id, &rec.id).await?;
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
        let cfg = CloudflareConfig::new("token");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = CloudflareConfig::new("token");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn with_zone_id_validates_zone_name() {
        let cfg = CloudflareConfig::new("token");
        assert!(cfg.with_zone_id("localhost", "abc").is_err());
    }

    #[test]
    fn records_url_percent_encodes_zone_id() {
        let cfg = CloudflareConfig::new("token");
        let provider = CloudflareProvider::new(cfg).unwrap();
        let url = provider.records_url("foo/../bar");
        assert!(url.contains("foo%2F..%2Fbar"), "got {url}");
    }
}

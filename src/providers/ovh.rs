use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::dns::find_zone;
use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    api_error, encode_path, relative_name, validate_acme_value, validate_fqdn, validate_https_base,
    validate_zone, KeyedMutex,
};

const OVH_EU_API_BASE: &str = "https://eu.api.ovh.com/1.0";
const ENV_APP_KEY: &str = "OVH_APPLICATION_KEY";
const ENV_APP_SECRET: &str = "OVH_APPLICATION_SECRET";
const ENV_CONSUMER_KEY: &str = "OVH_CONSUMER_KEY";
const DEFAULT_TTL: u32 = 60;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER: &str = "ovh";

pub struct OvhConfig {
    application_key: SecretString,
    application_secret: SecretString,
    consumer_key: SecretString,
    api_base: String,
    zone_override: Option<String>,
}

impl OvhConfig {
    pub fn new(
        application_key: impl Into<String>,
        application_secret: impl Into<String>,
        consumer_key: impl Into<String>,
    ) -> Self {
        Self {
            application_key: SecretString::new(application_key.into().into()),
            application_secret: SecretString::new(application_secret.into().into()),
            consumer_key: SecretString::new(consumer_key.into().into()),
            api_base: OVH_EU_API_BASE.to_string(),
            zone_override: None,
        }
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        validate_https_base(&base, PROVIDER)?;
        self.api_base = base;
        Ok(self)
    }

    /// Skip the SOA lookup and use `zone` directly. Useful when the caller
    /// already knows the apex (avoids a DNS round-trip) or in tests that
    /// don't have a real resolver.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(zone);
        Ok(self)
    }
}

pub struct OvhProvider {
    config: OvhConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
}

impl OvhProvider {
    pub fn new(config: OvhConfig) -> Result<Self, DnsError> {
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
        let ak =
            env::var(ENV_APP_KEY).map_err(|_| DnsError::MissingCredentials(ENV_APP_KEY.into()))?;
        let asec = env::var(ENV_APP_SECRET)
            .map_err(|_| DnsError::MissingCredentials(ENV_APP_SECRET.into()))?;
        let ck = env::var(ENV_CONSUMER_KEY)
            .map_err(|_| DnsError::MissingCredentials(ENV_CONSUMER_KEY.into()))?;
        Self::new(OvhConfig::new(ak, asec, ck))
    }

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

    fn record_list_url(&self, zone: &str) -> String {
        format!(
            "{}/domain/zone/{}/record",
            self.config.api_base,
            encode_path(zone)
        )
    }

    fn record_item_url(&self, zone: &str, id: u64) -> String {
        format!(
            "{}/domain/zone/{}/record/{}",
            self.config.api_base,
            encode_path(zone),
            id
        )
    }

    fn refresh_url(&self, zone: &str) -> String {
        format!(
            "{}/domain/zone/{}/refresh",
            self.config.api_base,
            encode_path(zone)
        )
    }

    fn ovh_path(suffix: &str) -> String {
        format!("/domain/zone/{suffix}")
    }

    /// Build the X-Ovh-Signature header value for a request.
    ///
    /// OVH signs as `"$1$" + sha1_hex(secret + "+" + consumer_key + "+" +
    /// method + "+" + full_url + "+" + body + "+" + timestamp)`.
    fn sign_request(&self, method: &str, url: &str, body: &str, timestamp: i64) -> String {
        let mut hasher = Sha1::new();
        hasher.update(self.config.application_secret.expose_secret().as_bytes());
        hasher.update(b"+");
        hasher.update(self.config.consumer_key.expose_secret().as_bytes());
        hasher.update(b"+");
        hasher.update(method.as_bytes());
        hasher.update(b"+");
        hasher.update(url.as_bytes());
        hasher.update(b"+");
        hasher.update(body.as_bytes());
        hasher.update(b"+");
        hasher.update(timestamp.to_string().as_bytes());
        format!("$1${}", hex::encode(hasher.finalize()))
    }

    fn now_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn signed_request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: &str,
    ) -> reqwest::RequestBuilder {
        let ts = Self::now_timestamp();
        let signature = self.sign_request(method.as_str(), url, body, ts);
        let mut req = self
            .http
            .request(method, url)
            .header(
                "X-Ovh-Application",
                self.config.application_key.expose_secret(),
            )
            .header("X-Ovh-Consumer", self.config.consumer_key.expose_secret())
            .header("X-Ovh-Timestamp", ts.to_string())
            .header("X-Ovh-Signature", signature);
        if !body.is_empty() {
            req = req
                .header("Content-Type", "application/json")
                .body(body.to_string());
        }
        req
    }

    async fn list_records(&self, zone: &str, sub_domain: &str) -> Result<Vec<u64>, DnsError> {
        let url = format!(
            "{}?fieldType=TXT&subDomain={}",
            self.record_list_url(zone),
            encode_path(sub_domain)
        );
        let response = self
            .signed_request(reqwest::Method::GET, &url, "")
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(api_error(
                PROVIDER,
                "GET",
                Self::ovh_path(&format!("{zone}/record")),
                status,
                response,
            )
            .await);
        }
        let ids: Vec<u64> = response.json().await?;
        Ok(ids)
    }

    async fn get_record(&self, zone: &str, id: u64) -> Result<OvhRecord, DnsError> {
        let url = self.record_item_url(zone, id);
        let response = self
            .signed_request(reqwest::Method::GET, &url, "")
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(api_error(
                PROVIDER,
                "GET",
                Self::ovh_path(&format!("{zone}/record/{id}")),
                status,
                response,
            )
            .await);
        }
        let record: OvhRecord = response.json().await?;
        Ok(record)
    }

    async fn create_record(
        &self,
        zone: &str,
        sub_domain: &str,
        target: &str,
    ) -> Result<(), DnsError> {
        let url = self.record_list_url(zone);
        let body = serde_json::to_string(&CreateRecordBody {
            field_type: "TXT",
            sub_domain,
            target,
            ttl: DEFAULT_TTL,
        })
        .map_err(|e| DnsError::Other(format!("serialize ovh create body: {e}")))?;
        let response = self
            .signed_request(reqwest::Method::POST, &url, &body)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(api_error(
                PROVIDER,
                "POST",
                Self::ovh_path(&format!("{zone}/record")),
                status,
                response,
            )
            .await);
        }
        Ok(())
    }

    async fn delete_record(&self, zone: &str, id: u64) -> Result<(), DnsError> {
        let url = self.record_item_url(zone, id);
        let response = self
            .signed_request(reqwest::Method::DELETE, &url, "")
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() && status.as_u16() != 404 {
            return Err(api_error(
                PROVIDER,
                "DELETE",
                Self::ovh_path(&format!("{zone}/record/{id}")),
                status,
                response,
            )
            .await);
        }
        Ok(())
    }

    async fn refresh_zone(&self, zone: &str) -> Result<(), DnsError> {
        let url = self.refresh_url(zone);
        let response = self
            .signed_request(reqwest::Method::POST, &url, "")
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(api_error(
                PROVIDER,
                "POST",
                Self::ovh_path(&format!("{zone}/refresh")),
                status,
                response,
            )
            .await);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct CreateRecordBody<'a> {
    #[serde(rename = "fieldType")]
    field_type: &'a str,
    #[serde(rename = "subDomain")]
    sub_domain: &'a str,
    target: &'a str,
    ttl: u32,
}

#[derive(Deserialize)]
struct OvhRecord {
    id: u64,
    target: String,
}

impl DnsProvider for OvhProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        validate_acme_value(value)?;
        let zone = self.resolve_zone(fqdn).await?;
        let sub_domain = relative_name(fqdn, &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{sub_domain}")).await;

        // OVH stores each TXT line as its own record. Check existing records
        // so we don't create a duplicate if present was called twice for the
        // same value (e.g. a retry).
        let existing_ids = self.list_records(&zone, &sub_domain).await?;
        for id in &existing_ids {
            let record = self.get_record(&zone, *id).await?;
            // OVH wraps TXT values in double quotes; strip them for compare.
            let stored = record.target.trim_matches('"');
            if stored == value {
                return Ok(());
            }
        }

        self.create_record(&zone, &sub_domain, value).await?;
        self.refresh_zone(&zone).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone = self.resolve_zone(fqdn).await?;
        let sub_domain = relative_name(fqdn, &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{sub_domain}")).await;

        let existing_ids = self.list_records(&zone, &sub_domain).await?;
        let mut deleted_any = false;
        for id in existing_ids {
            let record = self.get_record(&zone, id).await?;
            let stored = record.target.trim_matches('"');
            if stored == value {
                self.delete_record(&zone, record.id).await?;
                deleted_any = true;
            }
        }

        if deleted_any {
            self.refresh_zone(&zone).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_api_base_rejects_non_https() {
        let cfg = OvhConfig::new("ak", "as", "ck");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = OvhConfig::new("ak", "as", "ck");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn sign_request_is_deterministic() {
        let cfg = OvhConfig::new("ak", "secret-value", "consumer-key");
        let provider = OvhProvider::new(cfg).unwrap();
        let s1 = provider.sign_request("GET", "https://example/test", "", 1_700_000_000);
        let s2 = provider.sign_request("GET", "https://example/test", "", 1_700_000_000);
        assert_eq!(s1, s2);
        assert!(s1.starts_with("$1$"));
        // 40 hex chars + "$1$" prefix
        assert_eq!(s1.len(), 43);
    }

    #[test]
    fn sign_request_changes_with_inputs() {
        let cfg = OvhConfig::new("ak", "secret-value", "consumer-key");
        let provider = OvhProvider::new(cfg).unwrap();
        let base = provider.sign_request("GET", "https://example/a", "", 1);
        let diff_method = provider.sign_request("POST", "https://example/a", "", 1);
        let diff_url = provider.sign_request("GET", "https://example/b", "", 1);
        let diff_body = provider.sign_request("GET", "https://example/a", "x", 1);
        let diff_ts = provider.sign_request("GET", "https://example/a", "", 2);
        assert_ne!(base, diff_method);
        assert_ne!(base, diff_url);
        assert_ne!(base, diff_body);
        assert_ne!(base, diff_ts);
    }
}

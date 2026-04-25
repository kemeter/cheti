use std::env;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::dns::find_zone;
use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    api_error, encode_path, relative_name, validate_acme_value, validate_fqdn, validate_https_base,
    KeyedMutex,
};

const SCW_API_BASE: &str = "https://api.scaleway.com";
const ENV_SECRET_KEY: &str = "SCW_SECRET_KEY";
const DEFAULT_TTL: u32 = 300;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER: &str = "scaleway";

pub struct ScalewayConfig {
    secret_key: SecretString,
    api_base: String,
}

impl ScalewayConfig {
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            secret_key: SecretString::new(secret_key.into().into()),
            api_base: SCW_API_BASE.to_string(),
        }
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        validate_https_base(&base, PROVIDER)?;
        self.api_base = base;
        Ok(self)
    }
}

pub struct ScalewayProvider {
    config: ScalewayConfig,
    http: reqwest::Client,
    locks: KeyedMutex,
}

impl ScalewayProvider {
    pub fn new(config: ScalewayConfig) -> Result<Self, DnsError> {
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
        let key = env::var(ENV_SECRET_KEY)
            .map_err(|_| DnsError::MissingCredentials(ENV_SECRET_KEY.into()))?;
        Self::new(ScalewayConfig::new(key))
    }

    fn records_url(&self, zone: &str) -> String {
        format!(
            "{}/domain/v2beta1/dns-zones/{}/records",
            self.config.api_base,
            encode_path(zone)
        )
    }

    fn records_path(zone: &str) -> String {
        format!("/domain/v2beta1/dns-zones/{}/records", encode_path(zone))
    }

    async fn fetch_existing(&self, zone: &str, rname: &str) -> Result<Vec<String>, DnsError> {
        let url = self.records_url(zone);
        let response = self
            .http
            .get(&url)
            .header("X-Auth-Token", self.config.secret_key.expose_secret())
            .query(&[("name", rname), ("type", "TXT")])
            .send()
            .await?;

        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(Vec::new());
        }
        if !status.is_success() {
            return Err(
                api_error(PROVIDER, "GET", Self::records_path(zone), status, response).await,
            );
        }

        let body: RecordsResponse = response.json().await?;
        Ok(body
            .records
            .into_iter()
            .filter(|r| r.r#type == "TXT")
            .map(|r| r.data)
            .collect())
    }

    async fn apply_set(&self, zone: &str, rname: &str, values: &[String]) -> Result<(), DnsError> {
        let url = self.records_url(zone);
        let id_fields = IdFields {
            name: rname.to_string(),
            r#type: "TXT".to_string(),
        };
        let records: Vec<RecordSpec> = values
            .iter()
            .map(|v| RecordSpec {
                name: id_fields.name.clone(),
                r#type: id_fields.r#type.clone(),
                data: v.clone(),
                ttl: DEFAULT_TTL,
            })
            .collect();

        let body = ChangeRequest {
            changes: vec![Change::Set {
                set: SetChange { id_fields, records },
            }],
            return_all_records: false,
        };

        let response = self
            .http
            .patch(&url)
            .header("X-Auth-Token", self.config.secret_key.expose_secret())
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(api_error(
                PROVIDER,
                "PATCH",
                Self::records_path(zone),
                status,
                response,
            )
            .await);
        }
        Ok(())
    }

    async fn apply_delete(&self, zone: &str, rname: &str) -> Result<(), DnsError> {
        let url = self.records_url(zone);
        let body = ChangeRequest {
            changes: vec![Change::Delete {
                delete: IdFields {
                    name: rname.to_string(),
                    r#type: "TXT".to_string(),
                },
            }],
            return_all_records: false,
        };

        let response = self
            .http
            .patch(&url)
            .header("X-Auth-Token", self.config.secret_key.expose_secret())
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() && status.as_u16() != 404 {
            return Err(api_error(
                PROVIDER,
                "PATCH",
                Self::records_path(zone),
                status,
                response,
            )
            .await);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RecordsResponse {
    records: Vec<Record>,
}

#[derive(Deserialize)]
struct Record {
    r#type: String,
    data: String,
}

#[derive(Serialize)]
struct ChangeRequest {
    changes: Vec<Change>,
    return_all_records: bool,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Change {
    Set { set: SetChange },
    Delete { delete: IdFields },
}

#[derive(Serialize)]
struct SetChange {
    #[serde(flatten)]
    id_fields: IdFields,
    records: Vec<RecordSpec>,
}

#[derive(Serialize)]
struct IdFields {
    name: String,
    r#type: String,
}

#[derive(Serialize)]
struct RecordSpec {
    name: String,
    r#type: String,
    data: String,
    ttl: u32,
}

impl DnsProvider for ScalewayProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        validate_acme_value(value)?;
        let zone = find_zone(fqdn).await?;
        validate_fqdn(&zone)?;
        let rname = relative_name(fqdn, &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;
        let mut values = self.fetch_existing(&zone, &rname).await?;
        let owned_value = value.to_string();
        if !values.contains(&owned_value) {
            values.push(owned_value);
        }
        self.apply_set(&zone, &rname, &values).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone = find_zone(fqdn).await?;
        validate_fqdn(&zone)?;
        let rname = relative_name(fqdn, &zone)?;

        let _guard = self.locks.lock(&format!("{zone}|{rname}")).await;
        let values = self.fetch_existing(&zone, &rname).await?;
        let remaining: Vec<String> = values.into_iter().filter(|v| v != value).collect();

        if remaining.is_empty() {
            self.apply_delete(&zone, &rname).await
        } else {
            self.apply_set(&zone, &rname, &remaining).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_api_base_rejects_non_https() {
        let cfg = ScalewayConfig::new("dummy");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = ScalewayConfig::new("dummy");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn records_url_percent_encodes_zone() {
        let cfg = ScalewayConfig::new("dummy");
        let provider = ScalewayProvider::new(cfg).unwrap();
        let url = provider.records_url("foo/../bar");
        assert!(url.contains("foo%2F..%2Fbar"), "got {url}");
        assert!(!url.contains("foo/../bar"), "got {url}");
    }
}

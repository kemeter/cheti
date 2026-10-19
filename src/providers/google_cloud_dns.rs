use async_trait::async_trait;
use std::env;
use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::PrivatePkcs8KeyDer;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::Instant;

use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    api_error, encode_path, validate_acme_value, validate_fqdn, validate_https_base, KeyedMutex,
};

const GCDNS_API_BASE: &str = "https://dns.googleapis.com/dns/v1";
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// Path of the service account key file, as used by Google's own libraries.
const ENV_CREDENTIALS: &str = "GOOGLE_APPLICATION_CREDENTIALS";
const SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";
const JWT_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Lifetime requested for the signed assertion; Google caps it at one hour.
const JWT_LIFETIME: Duration = Duration::from_secs(3600);
/// An access token is renewed this long before it expires, so a request never
/// goes out with a token that lapses in flight.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);
/// TTL given to a TXT RRSet created by `present`. An existing RRSet keeps its
/// own TTL.
const DEFAULT_TTL: u32 = 60;
/// Upper bound on followed pages, so a misbehaving API cannot loop forever.
const MAX_PAGES: u32 = 50;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Changes are applied asynchronously; they are polled until they are done.
const CHANGE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const CHANGE_TIMEOUT: Duration = Duration::from_secs(60);
const PROVIDER: &str = "google-cloud-dns";

/// Configuration for the Google Cloud DNS provider, authenticated with a
/// service account key.
pub struct GoogleCloudDnsConfig {
    client_email: String,
    private_key: SecretString,
    private_key_id: Option<String>,
    token_uri: String,
    project: String,
    api_base: String,
    managed_zone: Option<String>,
}

impl GoogleCloudDnsConfig {
    /// Builds the configuration from the content of a service account JSON
    /// key. The project defaults to the key's `project_id`.
    pub fn from_service_account_json(json: &str) -> Result<Self, DnsError> {
        // The serde error never quotes string values, so it cannot leak the key.
        let key: ServiceAccountKey = serde_json::from_str(json)
            .map_err(|e| DnsError::Other(format!("{PROVIDER} invalid service account key: {e}")))?;
        if let Some(kind) = &key.kind {
            if kind != "service_account" {
                return Err(DnsError::Other(format!(
                    "{PROVIDER} credentials must be a service account key, got type {kind}"
                )));
            }
        }
        let token_uri = key
            .token_uri
            .unwrap_or_else(|| DEFAULT_TOKEN_URI.to_string());
        validate_https_base(&token_uri, PROVIDER)?;
        let project = key.project_id.unwrap_or_default();
        if !project.is_empty() {
            validate_project(&project)?;
        }
        Ok(Self {
            client_email: key.client_email,
            private_key: SecretString::new(key.private_key.into()),
            private_key_id: key.private_key_id,
            token_uri,
            project,
            api_base: GCDNS_API_BASE.to_string(),
            managed_zone: None,
        })
    }

    /// Reads a service account JSON key from `path`.
    pub fn from_service_account_file(path: impl AsRef<Path>) -> Result<Self, DnsError> {
        let path = path.as_ref();
        let json = std::fs::read_to_string(path).map_err(|e| {
            DnsError::MissingCredentials(format!(
                "{PROVIDER} cannot read service account key {}: {e}",
                path.display()
            ))
        })?;
        Self::from_service_account_json(&json)
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        validate_https_base(&base, PROVIDER)?;
        self.api_base = base.trim_end_matches('/').to_string();
        Ok(self)
    }

    /// Overrides the OAuth2 token endpoint taken from the key (`token_uri`).
    pub fn with_token_uri(mut self, token_uri: impl Into<String>) -> Result<Self, DnsError> {
        let uri = token_uri.into();
        validate_https_base(&uri, PROVIDER)?;
        self.token_uri = uri;
        Ok(self)
    }

    /// Manages zones of `project` instead of the key's own project.
    pub fn with_project(mut self, project: impl Into<String>) -> Result<Self, DnsError> {
        let project = project.into();
        validate_project(&project)?;
        self.project = project;
        Ok(self)
    }

    /// Skip the zone lookup and use the managed zone `name` (the zone's
    /// resource name, not its DNS name). The fqdn must be at-or-below it.
    pub fn with_managed_zone(mut self, name: impl Into<String>) -> Result<Self, DnsError> {
        let name = name.into();
        if name.is_empty() || name.len() > 63 {
            return Err(DnsError::Other(format!(
                "{PROVIDER} invalid managed zone name: {name}"
            )));
        }
        self.managed_zone = Some(name);
        Ok(self)
    }
}

impl fmt::Debug for GoogleCloudDnsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleCloudDnsConfig")
            .field("client_email", &self.client_email)
            .field("private_key", &"[redacted]")
            .field("token_uri", &self.token_uri)
            .field("project", &self.project)
            .field("api_base", &self.api_base)
            .field("managed_zone", &self.managed_zone)
            .finish()
    }
}

/// Project ids are made of lowercase letters, digits and hyphens; legacy
/// domain-scoped ids also contain `.` and `:`.
fn validate_project(project: &str) -> Result<(), DnsError> {
    let valid = !project.is_empty()
        && project.len() <= 100
        && project
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.:".contains(&b));
    if !valid {
        return Err(DnsError::Other(format!(
            "{PROVIDER} invalid project id: {project}"
        )));
    }
    Ok(())
}

pub struct GoogleCloudDnsProvider {
    config: GoogleCloudDnsConfig,
    key: RsaKeyPair,
    rng: SystemRandom,
    http: reqwest::Client,
    token: AsyncMutex<Option<CachedToken>>,
    locks: KeyedMutex,
}

struct CachedToken {
    value: SecretString,
    refresh_at: Instant,
}

impl GoogleCloudDnsProvider {
    pub fn new(config: GoogleCloudDnsConfig) -> Result<Self, DnsError> {
        if config.project.is_empty() {
            return Err(DnsError::MissingCredentials(format!(
                "{PROVIDER} project id (not in the key, set it with with_project)"
            )));
        }
        let der = PrivatePkcs8KeyDer::from_pem_slice(config.private_key.expose_secret().as_bytes())
            .map_err(|_| {
                DnsError::Other(format!(
                    "{PROVIDER} private_key is not a PKCS#8 PEM private key"
                ))
            })?;
        let key = RsaKeyPair::from_pkcs8(der.secret_pkcs8_der()).map_err(|e| {
            DnsError::Other(format!(
                "{PROVIDER} private_key is not a usable RSA key: {e}"
            ))
        })?;
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(DnsError::Http)?;
        Ok(Self {
            config,
            key,
            rng: SystemRandom::new(),
            http,
            token: AsyncMutex::new(None),
            locks: KeyedMutex::new(PROVIDER),
        })
    }

    /// Reads the service account key from the file named by
    /// `GOOGLE_APPLICATION_CREDENTIALS`.
    pub fn from_env() -> Result<Self, DnsError> {
        let path = env::var(ENV_CREDENTIALS)
            .map_err(|_| DnsError::MissingCredentials(ENV_CREDENTIALS.into()))?;
        Self::new(GoogleCloudDnsConfig::from_service_account_file(path)?)
    }

    fn zones_path(&self) -> String {
        format!(
            "/projects/{}/managedZones",
            encode_path(&self.config.project)
        )
    }

    fn zone_path(&self, zone: &str) -> String {
        format!("{}/{}", self.zones_path(), encode_path(zone))
    }

    /// Returns a valid access token, exchanging a fresh signed assertion when
    /// the cached one is missing or about to expire. The lock is held during
    /// the exchange so concurrent callers share a single token request.
    async fn access_token(&self) -> Result<String, DnsError> {
        let mut cached = self.token.lock().await;
        if let Some(token) = cached.as_ref() {
            if Instant::now() < token.refresh_at {
                return Ok(token.value.expose_secret().to_string());
            }
        }

        let assertion = self.signed_assertion()?;
        let response = self
            .http
            .post(&self.config.token_uri)
            .form(&[("grant_type", JWT_GRANT_TYPE), ("assertion", &assertion)])
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            // The token endpoint answers 400 `invalid_grant` for a revoked key
            // or a bad signature: all failures here are credential problems.
            let err = api_error(PROVIDER, "POST", "token".into(), status, response).await;
            return Err(into_auth(err));
        }

        let body: TokenResponse = response.json().await?;
        let lifetime = Duration::from_secs(body.expires_in.unwrap_or(3600));
        let token = CachedToken {
            value: SecretString::new(body.access_token.into()),
            refresh_at: Instant::now() + lifetime.saturating_sub(TOKEN_REFRESH_MARGIN),
        };
        let value = token.value.expose_secret().to_string();
        *cached = Some(token);
        Ok(value)
    }

    /// Builds the RS256 JWT exchanged for an access token (RFC 7523).
    fn signed_assertion(&self) -> Result<String, DnsError> {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DnsError::Other("system clock is before the unix epoch".into()))?
            .as_secs();
        let header = JwtHeader {
            alg: "RS256",
            typ: "JWT",
            kid: self.config.private_key_id.as_deref(),
        };
        let claims = JwtClaims {
            iss: &self.config.client_email,
            scope: SCOPE,
            aud: &self.config.token_uri,
            iat,
            exp: iat + JWT_LIFETIME.as_secs(),
        };
        let signing_input = format!(
            "{}.{}",
            BASE64URL_NOPAD.encode(&serde_json::to_vec(&header).map_err(json_err)?),
            BASE64URL_NOPAD.encode(&serde_json::to_vec(&claims).map_err(json_err)?)
        );
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &self.rng,
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| DnsError::Other(format!("{PROVIDER} failed to sign the JWT")))?;
        Ok(format!(
            "{signing_input}.{}",
            BASE64URL_NOPAD.encode(&signature)
        ))
    }

    async fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<reqwest::Response, DnsError> {
        let token = self.access_token().await?;
        let response = self
            .http
            .get(format!("{}{path}", self.config.api_base))
            .query(query)
            .bearer_auth(token)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            self.forget_token_on_unauthorized(status).await;
            return Err(check_error("GET", path.to_string(), status, response).await);
        }
        Ok(response)
    }

    /// A 401 means the cached token was revoked or expired early: drop it so
    /// the next operation exchanges a fresh one instead of failing until the
    /// cached expiry.
    async fn forget_token_on_unauthorized(&self, status: reqwest::StatusCode) {
        if status == reqwest::StatusCode::UNAUTHORIZED {
            *self.token.lock().await = None;
        }
    }

    /// Finds the managed zone owning `fqdn`: the public zone with the longest
    /// DNS name that is a suffix of it. Private zones are skipped, as public
    /// resolvers (and the CA) never see them.
    async fn resolve_zone(&self, fqdn: &str) -> Result<String, DnsError> {
        if let Some(zone) = &self.config.managed_zone {
            return Ok(zone.clone());
        }

        let name = absolute(fqdn);
        let path = self.zones_path();
        let mut best: Option<(usize, String)> = None;
        let mut page_token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let query: Vec<(&str, &str)> = match &page_token {
                Some(t) => vec![("pageToken", t.as_str())],
                None => Vec::new(),
            };
            let body: ManagedZones = self.get(&path, &query).await?.json().await?;
            for zone in body.managed_zones {
                if zone.visibility.as_deref() == Some("private") {
                    continue;
                }
                let dns_name = zone.dns_name.to_ascii_lowercase();
                let matches = name == dns_name || name.ends_with(&format!(".{dns_name}"));
                if matches && best.as_ref().is_none_or(|(len, _)| dns_name.len() > *len) {
                    best = Some((dns_name.len(), zone.name));
                }
            }
            match body.next_page_token {
                Some(t) if !t.is_empty() => page_token = Some(t),
                _ => {
                    return best
                        .map(|(_, zone)| zone)
                        .ok_or_else(|| DnsError::ZoneNotFound(fqdn.to_string()));
                }
            }
        }
        Err(DnsError::Api(format!(
            "{PROVIDER} zone listing exceeded {MAX_PAGES} pages"
        )))
    }

    /// Returns the TXT RRSet at `name` exactly as the API reports it, or
    /// `None` when it does not exist.
    async fn fetch_rrset(&self, zone: &str, name: &str) -> Result<Option<Value>, DnsError> {
        let path = format!("{}/rrsets", self.zone_path(zone));
        let body: RrsetList = self
            .get(&path, &[("name", name), ("type", "TXT")])
            .await?
            .json()
            .await?;
        Ok(body.rrsets.into_iter().find(|r| {
            r["type"] == "TXT"
                && r["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
        }))
    }

    /// Atomically replaces the RRSet: the current one is deleted exactly as
    /// fetched (the API rejects the change if it no longer matches) and the
    /// new one, if any, is added. Waits for the change to be applied.
    async fn apply_change(
        &self,
        zone: &str,
        deletion: Option<Value>,
        addition: Option<Rrset>,
    ) -> Result<(), DnsError> {
        let path = format!("{}/changes", self.zone_path(zone));
        let body = ChangeRequest {
            additions: addition.into_iter().collect(),
            deletions: deletion.into_iter().collect(),
        };
        let token = self.access_token().await?;
        let response = self
            .http
            .post(format!("{}{path}", self.config.api_base))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            self.forget_token_on_unauthorized(status).await;
            return Err(check_error("POST", path, status, response).await);
        }

        let change: Change = response.json().await?;
        self.wait_for_change(zone, change).await
    }

    async fn wait_for_change(&self, zone: &str, mut change: Change) -> Result<(), DnsError> {
        let deadline = Instant::now() + CHANGE_TIMEOUT;
        loop {
            if change.status == "done" {
                return Ok(());
            }
            if Instant::now() + CHANGE_POLL_INTERVAL > deadline {
                return Err(DnsError::Api(format!(
                    "{PROVIDER} change {} still {} after {}s",
                    change.id,
                    change.status,
                    CHANGE_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(CHANGE_POLL_INTERVAL).await;
            let path = format!(
                "{}/changes/{}",
                self.zone_path(zone),
                encode_path(&change.id)
            );
            change = self.get(&path, &[]).await?.json().await?;
        }
    }
}

/// Maps a failed response to a `DnsError`: credential problems become
/// `DnsError::Auth`, and throttling and concurrent modifications get an
/// explicit message.
async fn check_error(
    method: &str,
    path: String,
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> DnsError {
    match status {
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
            into_auth(api_error(PROVIDER, method, path, status, response).await)
        }
        reqwest::StatusCode::TOO_MANY_REQUESTS => {
            let hint = match response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
            {
                Some(delay) => format!("retry after {delay}s"),
                None => "retry later".to_string(),
            };
            DnsError::Api(format!(
                "{PROVIDER} {method} {path} was rate limited (429), {hint}"
            ))
        }
        // 409 when the RRSet to add already exists, 412 when the RRSet to
        // delete no longer matches: another writer changed it in between.
        reqwest::StatusCode::CONFLICT | reqwest::StatusCode::PRECONDITION_FAILED => {
            DnsError::Api(format!(
                "{PROVIDER} {method} {path} returned {status}: the record set was modified concurrently, retry the operation"
            ))
        }
        _ => api_error(PROVIDER, method, path, status, response).await,
    }
}

fn into_auth(err: DnsError) -> DnsError {
    match err {
        DnsError::Api(msg) => DnsError::Auth(msg),
        other => other,
    }
}

fn json_err(e: serde_json::Error) -> DnsError {
    DnsError::Other(format!("{PROVIDER} JSON encoding failed: {e}"))
}

/// Cloud DNS names are absolute, with a trailing dot.
fn absolute(fqdn: &str) -> String {
    format!("{}.", fqdn.trim_end_matches('.').to_ascii_lowercase())
}

/// TXT values are exchanged in presentation format: `"value"`. ACME values
/// are base64url, so they are never split into several character strings.
fn unquote(record: &str) -> String {
    let trimmed = record.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
        .to_string()
}

/// The TXT values of a fetched RRSet, quoted as the API returns them.
fn rrdatas(rrset: &Value) -> Vec<String> {
    rrset["rrdatas"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct ServiceAccountKey {
    #[serde(rename = "type")]
    kind: Option<String>,
    client_email: String,
    private_key: String,
    private_key_id: Option<String>,
    token_uri: Option<String>,
    project_id: Option<String>,
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedZones {
    #[serde(default)]
    managed_zones: Vec<ManagedZone>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedZone {
    name: String,
    dns_name: String,
    visibility: Option<String>,
}

#[derive(Deserialize)]
struct RrsetList {
    #[serde(default)]
    rrsets: Vec<Value>,
}

#[derive(Serialize)]
struct Rrset {
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
    ttl: u64,
    rrdatas: Vec<String>,
}

#[derive(Serialize)]
struct ChangeRequest {
    additions: Vec<Rrset>,
    deletions: Vec<Value>,
}

#[derive(Deserialize)]
struct Change {
    id: String,
    status: String,
}

#[async_trait]
impl DnsProvider for GoogleCloudDnsProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        validate_acme_value(value)?;
        let zone = self.resolve_zone(fqdn).await?;
        let name = absolute(fqdn);

        let _guard = self.locks.lock(&format!("{zone}|{name}")).await;
        let existing = self.fetch_rrset(&zone, &name).await?;
        // The RRSet is shared with other values (e.g. a wildcard and its apex
        // sharing `_acme-challenge`): the new value is merged into it, keeping
        // its TTL.
        let (mut values, ttl) = match &existing {
            Some(rrset) => (
                rrdatas(rrset),
                rrset["ttl"].as_u64().unwrap_or(u64::from(DEFAULT_TTL)),
            ),
            None => (Vec::new(), u64::from(DEFAULT_TTL)),
        };
        if values.iter().any(|v| unquote(v) == value) {
            return Ok(());
        }
        values.push(format!("\"{value}\""));
        let addition = Rrset {
            name,
            kind: "TXT",
            ttl,
            rrdatas: values,
        };
        self.apply_change(&zone, existing, Some(addition)).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone = self.resolve_zone(fqdn).await?;
        let name = absolute(fqdn);

        let _guard = self.locks.lock(&format!("{zone}|{name}")).await;
        let Some(existing) = self.fetch_rrset(&zone, &name).await? else {
            return Ok(());
        };
        let values = rrdatas(&existing);
        let remaining: Vec<String> = values
            .iter()
            .filter(|v| unquote(v) != value)
            .cloned()
            .collect();
        if remaining.len() == values.len() {
            return Ok(());
        }
        // Removing the last value deletes the RRSet.
        let addition = (!remaining.is_empty()).then(|| Rrset {
            name,
            kind: "TXT",
            ttl: existing["ttl"].as_u64().unwrap_or(u64::from(DEFAULT_TTL)),
            rrdatas: remaining,
        });
        self.apply_change(&zone, Some(existing), addition).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_json(extra: &str) -> String {
        format!(
            r#"{{"type":"service_account","project_id":"my-project","client_email":"dns@my-project.iam.gserviceaccount.com","private_key":"not-a-key"{extra}}}"#
        )
    }

    #[test]
    fn with_api_base_rejects_non_https() {
        let cfg = GoogleCloudDnsConfig::from_service_account_json(&key_json("")).unwrap();
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = GoogleCloudDnsConfig::from_service_account_json(&key_json("")).unwrap();
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn token_uri_from_key_must_be_https() {
        let json = key_json(r#","token_uri":"http://evil.example/token""#);
        assert!(GoogleCloudDnsConfig::from_service_account_json(&json).is_err());
    }

    #[test]
    fn with_token_uri_rejects_non_https() {
        let cfg = GoogleCloudDnsConfig::from_service_account_json(&key_json("")).unwrap();
        assert!(cfg.with_token_uri("http://evil.example/token").is_err());
    }

    #[test]
    fn rejects_non_service_account_credentials() {
        let json = r#"{"type":"authorized_user","client_email":"a","private_key":"b"}"#;
        let err = GoogleCloudDnsConfig::from_service_account_json(json).unwrap_err();
        assert!(err.to_string().contains("authorized_user"), "{err}");
    }

    #[test]
    fn with_project_rejects_path_characters() {
        let cfg = GoogleCloudDnsConfig::from_service_account_json(&key_json("")).unwrap();
        assert!(cfg.with_project("foo/../bar").is_err());
    }

    #[test]
    fn debug_redacts_private_key() {
        let json = key_json("").replace("not-a-key", "SUPER-SECRET-KEY");
        let cfg = GoogleCloudDnsConfig::from_service_account_json(&json).unwrap();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("SUPER-SECRET-KEY"), "{debug}");
    }

    #[test]
    fn invalid_private_key_error_does_not_leak_it() {
        let json = key_json("").replace("not-a-key", "SUPER-SECRET-KEY");
        let cfg = GoogleCloudDnsConfig::from_service_account_json(&json).unwrap();
        let err = GoogleCloudDnsProvider::new(cfg).err().unwrap();
        assert!(!err.to_string().contains("SUPER-SECRET-KEY"), "{err}");
    }

    #[test]
    fn absolute_adds_single_trailing_dot() {
        assert_eq!(
            absolute("_acme-challenge.Example.com"),
            "_acme-challenge.example.com."
        );
        assert_eq!(absolute("example.com."), "example.com.");
    }

    #[test]
    fn unquote_strips_surrounding_quotes() {
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("abc"), "abc");
    }
}

use async_trait::async_trait;
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{
    truncate_error_body, validate_acme_value, validate_fqdn, validate_https_base, KeyedMutex,
};

const ROUTE53_API_BASE: &str = "https://route53.amazonaws.com/2013-04-01";
const ENV_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
const ENV_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const ENV_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
/// Route53 is a global service: requests are always signed for us-east-1.
const SIGNING_REGION: &str = "us-east-1";
const SIGNING_SERVICE: &str = "route53";
const XML_NAMESPACE: &str = "https://route53.amazonaws.com/doc/2013-04-01/";
/// TTL given to a TXT record set created by `present`. An existing record set
/// keeps its own TTL.
const DEFAULT_TTL: u32 = 60;
/// Hosted zones returned per name lookup. Route53 allows several zones with
/// the same name, so more than one is asked for to detect ambiguity.
const ZONE_LOOKUP_MAX_ITEMS: &str = "100";
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Changes are applied asynchronously; they are polled until INSYNC.
const CHANGE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const CHANGE_TIMEOUT: Duration = Duration::from_secs(120);
const PROVIDER: &str = "route53";
/// Error codes meaning the credentials or their permissions were refused.
const AUTH_CODES: &[&str] = &[
    "AccessDenied",
    "AccessDeniedException",
    "ExpiredToken",
    "IncompleteSignature",
    "InvalidClientTokenId",
    "MissingAuthenticationToken",
    "SignatureDoesNotMatch",
    "UnrecognizedClientException",
];
/// Error codes meaning the request was throttled. `PriorRequestNotComplete`
/// is returned when changes to the same hosted zone come in too fast.
const THROTTLING_CODES: &[&str] = &["Throttling", "PriorRequestNotComplete"];

/// SigV4 URI encoding: everything but the unreserved characters
/// `A-Z a-z 0-9 - _ . ~` is percent-encoded.
const SIGV4_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Configuration for the AWS Route53 provider. Requests are signed with
/// AWS Signature Version 4.
pub struct Route53Config {
    access_key_id: String,
    secret_access_key: SecretString,
    session_token: Option<SecretString>,
    api_base: String,
    hosted_zone_id: Option<String>,
}

impl Route53Config {
    pub fn new(access_key_id: impl Into<String>, secret_access_key: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: SecretString::new(secret_access_key.into().into()),
            session_token: None,
            api_base: ROUTE53_API_BASE.to_string(),
            hosted_zone_id: None,
        }
    }

    /// Session token of temporary credentials (STS, assumed role), sent as
    /// `X-Amz-Security-Token`.
    pub fn with_session_token(mut self, session_token: impl Into<String>) -> Self {
        self.session_token = Some(SecretString::new(session_token.into().into()));
        self
    }

    /// Overrides the API base, including the `/2013-04-01` version prefix.
    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self, DnsError> {
        let base = api_base.into();
        validate_https_base(&base, PROVIDER)?;
        self.api_base = base.trim_end_matches('/').to_string();
        Ok(self)
    }

    /// Skip the zone lookup and use this hosted zone directly. Accepts the
    /// bare id (`Z0123456789ABC`) or the `/hostedzone/Z0123456789ABC` form
    /// returned by the API. The fqdn must be at-or-below the zone's name.
    /// This is also the way to target a private hosted zone.
    pub fn with_hosted_zone_id(mut self, id: impl Into<String>) -> Result<Self, DnsError> {
        let id = id.into();
        self.hosted_zone_id =
            Some(normalize_id(&id, "/hostedzone/").ok_or_else(|| {
                DnsError::Other(format!("invalid {PROVIDER} hosted zone id: {id}"))
            })?);
        Ok(self)
    }
}

pub struct Route53Provider {
    config: Route53Config,
    http: reqwest::Client,
    locks: KeyedMutex,
    /// Cached `fqdn -> hosted zone id` mapping, so `cleanup` does not repeat
    /// the walk done by `present`.
    zone_cache: Mutex<HashMap<String, String>>,
}

impl Route53Provider {
    pub fn new(config: Route53Config) -> Result<Self, DnsError> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(DnsError::Http)?;
        Ok(Self {
            config,
            http,
            locks: KeyedMutex::new(PROVIDER),
            zone_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and the optional
    /// `AWS_SESSION_TOKEN`.
    pub fn from_env() -> Result<Self, DnsError> {
        let access_key_id = env::var(ENV_ACCESS_KEY_ID)
            .map_err(|_| DnsError::MissingCredentials(ENV_ACCESS_KEY_ID.into()))?;
        let secret_access_key = env::var(ENV_SECRET_ACCESS_KEY)
            .map_err(|_| DnsError::MissingCredentials(ENV_SECRET_ACCESS_KEY.into()))?;
        let mut config = Route53Config::new(access_key_id, secret_access_key);
        if let Ok(token) = env::var(ENV_SESSION_TOKEN) {
            if !token.is_empty() {
                config = config.with_session_token(token);
            }
        }
        Self::new(config)
    }

    /// Sends a signed request and returns the body of a successful response.
    /// The query is built here, already in SigV4 canonical form, so the
    /// signed string and the sent one are the same.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<String>,
    ) -> Result<String, DnsError> {
        let mut raw_url = format!("{}{path}", self.config.api_base);
        let query = canonical_query(query);
        if !query.is_empty() {
            raw_url.push('?');
            raw_url.push_str(&query);
        }
        let url = Url::parse(&raw_url)
            .map_err(|e| DnsError::Other(format!("{PROVIDER} invalid request URL: {e}")))?;

        let payload = body.unwrap_or_default();
        let credentials = SigningCredentials {
            access_key_id: &self.config.access_key_id,
            secret_access_key: self.config.secret_access_key.expose_secret(),
            session_token: self
                .config
                .session_token
                .as_ref()
                .map(|t| t.expose_secret()),
        };
        let headers = sign_v4(
            &credentials,
            &SigningScope {
                region: SIGNING_REGION,
                service: SIGNING_SERVICE,
            },
            method.as_str(),
            &url,
            payload.as_bytes(),
            &amz_date_now(),
        );

        let mut request = self.http.request(method.clone(), url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if !payload.is_empty() {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/xml")
                .body(payload);
        }

        let response = request.send().await?;
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            return Err(map_error(method.as_str(), path, status, &text));
        }
        Ok(text)
    }

    /// Finds the hosted zone owning `fqdn`: the configured override, or the
    /// longest suffix of `fqdn` that is the name of a public hosted zone of
    /// the account. Private zones are skipped, as ACME servers validate
    /// against public DNS.
    async fn resolve_zone(&self, fqdn: &str) -> Result<String, DnsError> {
        if let Some(id) = &self.config.hosted_zone_id {
            return Ok(id.clone());
        }

        let name = normalize_name(fqdn);
        if let Some(id) = self.zone_cache.lock().unwrap().get(&name) {
            return Ok(id.clone());
        }

        let labels: Vec<&str> = name.split('.').collect();
        // A zone has at least two labels, so the bare TLD is never queried.
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            if let Some(id) = self.find_public_zone(&candidate).await? {
                self.zone_cache
                    .lock()
                    .unwrap()
                    .insert(name.clone(), id.clone());
                return Ok(id);
            }
        }
        Err(DnsError::ZoneNotFound(fqdn.to_string()))
    }

    /// Returns the id of the public hosted zone named `candidate`, if any.
    /// ListHostedZonesByName starts at `dnsname` in its own ordering, so only
    /// the entries whose name is exactly `candidate` are considered.
    async fn find_public_zone(&self, candidate: &str) -> Result<Option<String>, DnsError> {
        let path = "/hostedzonesbyname";
        let text = self
            .send(
                reqwest::Method::GET,
                path,
                &[("dnsname", candidate), ("maxitems", ZONE_LOOKUP_MAX_ITEMS)],
                None,
            )
            .await?;
        let body: ListHostedZonesByNameResponse = parse_xml("GET", path, &text)?;

        let public: Vec<&HostedZone> = body
            .hosted_zones
            .items
            .iter()
            .filter(|z| normalize_name(&z.name) == candidate)
            .filter(|z| !z.config.as_ref().is_some_and(|c| c.private_zone))
            .collect();
        match public.as_slice() {
            [] => Ok(None),
            [zone] => normalize_id(&zone.id, "/hostedzone/")
                .map(Some)
                .ok_or_else(|| {
                    DnsError::Api(format!(
                        "{PROVIDER} GET {path} returned an invalid hosted zone id"
                    ))
                }),
            _ => Err(DnsError::Api(format!(
                "{PROVIDER}: several public hosted zones are named {candidate}; \
                 pick one with with_hosted_zone_id"
            ))),
        }
    }

    /// Returns the TXT record set named `name` (absolute, with trailing dot),
    /// or `None` when it does not exist.
    async fn fetch_rrset(&self, zone_id: &str, name: &str) -> Result<Option<TxtSet>, DnsError> {
        let path = format!("/hostedzone/{zone_id}/rrset");
        let text = self
            .send(
                reqwest::Method::GET,
                &path,
                &[("name", name), ("type", "TXT"), ("maxitems", "1")],
                None,
            )
            .await?;
        let body: ListResourceRecordSetsResponse = parse_xml("GET", &path, &text)?;

        // The listing starts at name/type and goes on with whatever follows,
        // so the first set is only ours if both match.
        let Some(set) = body.resource_record_sets.items.into_iter().next() else {
            return Ok(None);
        };
        if normalize_name(&set.name) != normalize_name(name) || set.record_type != "TXT" {
            return Ok(None);
        }
        if set.set_identifier.is_some() {
            return Err(DnsError::Api(format!(
                "{PROVIDER}: TXT record set {name} uses a routing policy, which is not supported"
            )));
        }
        let values = set
            .resource_records
            .map(|r| r.items.into_iter().map(|r| r.value).collect())
            .unwrap_or_default();
        Ok(Some(TxtSet {
            ttl: set.ttl.unwrap_or(DEFAULT_TTL),
            values,
        }))
    }

    /// Applies a single change to the TXT record set and waits for it to be
    /// INSYNC.
    async fn change_rrset(
        &self,
        zone_id: &str,
        action: &str,
        name: &str,
        set: &TxtSet,
    ) -> Result<(), DnsError> {
        let path = format!("/hostedzone/{zone_id}/rrset/");
        let body = change_batch_xml(action, name, set);
        let text = self
            .send(reqwest::Method::POST, &path, &[], Some(body))
            .await?;
        let body: ChangeResponse = parse_xml("POST", &path, &text)?;
        self.wait_for_change(body.change_info).await
    }

    async fn wait_for_change(&self, mut change: ChangeInfo) -> Result<(), DnsError> {
        let deadline = tokio::time::Instant::now() + CHANGE_TIMEOUT;
        loop {
            if change.status == "INSYNC" {
                return Ok(());
            }
            if tokio::time::Instant::now() + CHANGE_POLL_INTERVAL > deadline {
                return Err(DnsError::Api(format!(
                    "{PROVIDER} change {} still {} after {}s",
                    change.id,
                    change.status,
                    CHANGE_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(CHANGE_POLL_INTERVAL).await;
            change = self.fetch_change(&change.id).await?;
        }
    }

    async fn fetch_change(&self, change_id: &str) -> Result<ChangeInfo, DnsError> {
        let id = normalize_id(change_id, "/change/")
            .ok_or_else(|| DnsError::Api(format!("{PROVIDER} returned an invalid change id")))?;
        let path = format!("/change/{id}");
        let text = self.send(reqwest::Method::GET, &path, &[], None).await?;
        let body: ChangeResponse = parse_xml("GET", &path, &text)?;
        Ok(body.change_info)
    }
}

/// A TXT record set as stored by Route53. Values are kept in presentation
/// format (quoted), so values written by others are sent back untouched.
struct TxtSet {
    ttl: u32,
    values: Vec<String>,
}

impl TxtSet {
    fn contains(&self, value: &str) -> bool {
        self.values.iter().any(|v| unquote(v) == value)
    }
}

/// Lower-cased name without trailing dot, for comparisons.
fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Strips the `/hostedzone/` or `/change/` prefix of an API id and checks
/// that what is left is safe to put in a path.
fn normalize_id(id: &str, prefix: &str) -> Option<String> {
    let id = id.strip_prefix(prefix).unwrap_or(id);
    let valid = !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric());
    valid.then(|| id.to_string())
}

/// TXT values are exchanged in presentation format: `"value"`. ACME values
/// are base64url, so they are never split into several character strings.
fn unquote(record: &str) -> &str {
    let trimmed = record.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
}

fn change_batch_xml(action: &str, name: &str, set: &TxtSet) -> String {
    use quick_xml::escape::escape;

    let records: String = set
        .values
        .iter()
        .map(|v| {
            format!(
                "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                escape(v)
            )
        })
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ChangeResourceRecordSetsRequest xmlns=\"{XML_NAMESPACE}\">\
         <ChangeBatch><Changes><Change>\
         <Action>{action}</Action>\
         <ResourceRecordSet>\
         <Name>{}</Name><Type>TXT</Type><TTL>{}</TTL>\
         <ResourceRecords>{records}</ResourceRecords>\
         </ResourceRecordSet>\
         </Change></Changes></ChangeBatch>\
         </ChangeResourceRecordSetsRequest>",
        escape(name),
        set.ttl,
    )
}

fn parse_xml<T: for<'de> Deserialize<'de>>(
    method: &str,
    path: &str,
    text: &str,
) -> Result<T, DnsError> {
    quick_xml::de::from_str(text).map_err(|e| {
        DnsError::Api(format!(
            "{PROVIDER} {method} {path} returned an unexpected body: {e}"
        ))
    })
}

/// Maps a failed response to a `DnsError` from its XML error document:
/// refused credentials become `Auth`, throttling gets an explicit message.
fn map_error(method: &str, path: &str, status: reqwest::StatusCode, text: &str) -> DnsError {
    let (code, message) = if let Ok(err) = quick_xml::de::from_str::<ErrorResponse>(text) {
        (err.error.code, err.error.message.unwrap_or_default())
    } else if let Ok(err) = quick_xml::de::from_str::<InvalidChangeBatch>(text) {
        (
            "InvalidChangeBatch".to_string(),
            err.messages.items.join("; "),
        )
    } else {
        let text = truncate_error_body(text.to_string());
        return if status == reqwest::StatusCode::FORBIDDEN {
            DnsError::Auth(format!(
                "{PROVIDER} {method} {path} returned {status}: {text}"
            ))
        } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            DnsError::Api(format!(
                "{PROVIDER} {method} {path} was rate limited ({status}), retry later"
            ))
        } else {
            DnsError::Api(format!(
                "{PROVIDER} {method} {path} returned {status}: {text}"
            ))
        };
    };
    let message = truncate_error_body(message);

    if AUTH_CODES.contains(&code.as_str()) {
        DnsError::Auth(format!(
            "{PROVIDER} {method} {path} refused credentials: {code}: {message}"
        ))
    } else if THROTTLING_CODES.contains(&code.as_str())
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        DnsError::Api(format!(
            "{PROVIDER} {method} {path} was rate limited ({code}), retry later: {message}"
        ))
    } else if code == "NoSuchHostedZone" {
        DnsError::ZoneNotFound(format!("{PROVIDER} hosted zone ({message})"))
    } else {
        DnsError::Api(format!(
            "{PROVIDER} {method} {path} returned {status}: {code}: {message}"
        ))
    }
}

// --- AWS Signature Version 4 -------------------------------------------------

struct SigningCredentials<'a> {
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: Option<&'a str>,
}

struct SigningScope<'a> {
    region: &'a str,
    service: &'a str,
}

/// Current time in the SigV4 `YYYYMMDDTHHMMSSZ` format.
fn amz_date_now() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Encodes and sorts query parameters as SigV4 expects. The result is also
/// what gets sent, so no re-encoding can make it diverge from the signature.
fn canonical_query(params: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(k, SIGV4_ENCODE).to_string(),
                utf8_percent_encode(v, SIGV4_ENCODE).to_string(),
            )
        })
        .collect();
    encoded.sort();
    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Canonical URI for services other than S3: each segment of the (already
/// percent-encoded) path is encoded once more.
fn canonical_uri(url: &Url) -> String {
    let path = url.path();
    if path.is_empty() {
        return "/".to_string();
    }
    path.split('/')
        .map(|s| utf8_percent_encode(s, SIGV4_ENCODE).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Value of the `Host` header the HTTP client sends for `url`.
fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Signs a request and returns the headers to add to it: `x-amz-date`, the
/// optional `x-amz-security-token`, and `authorization`. Signed headers are
/// `host`, `x-amz-date` and, with temporary credentials, the token.
fn sign_v4(
    credentials: &SigningCredentials<'_>,
    scope: &SigningScope<'_>,
    method: &str,
    url: &Url,
    payload: &[u8],
    amz_date: &str,
) -> Vec<(&'static str, String)> {
    let date = &amz_date[..8];

    let mut canonical_headers = vec![
        ("host", host_header(url)),
        ("x-amz-date", amz_date.to_string()),
    ];
    if let Some(token) = credentials.session_token {
        canonical_headers.push(("x-amz-security-token", token.to_string()));
    }
    let signed_headers = canonical_headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let header_block: String = canonical_headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();

    let canonical_request = format!(
        "{method}\n{}\n{}\n{header_block}\n{signed_headers}\n{}",
        canonical_uri(url),
        url.query().unwrap_or_default(),
        hex::encode(Sha256::digest(payload)),
    );

    let credential_scope = format!("{date}/{}/{}/aws4_request", scope.region, scope.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let secret = format!("AWS4{}", credentials.secret_access_key);
    let k_date = hmac_sha256(secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, scope.region.as_bytes());
    let k_service = hmac_sha256(&k_region, scope.service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let mut headers = vec![("x-amz-date", amz_date.to_string())];
    if let Some(token) = credentials.session_token {
        headers.push(("x-amz-security-token", token.to_string()));
    }
    headers.push((
        "authorization",
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, \
             SignedHeaders={signed_headers}, Signature={signature}",
            credentials.access_key_id
        ),
    ));
    headers
}

// --- XML documents -----------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListHostedZonesByNameResponse {
    #[serde(default)]
    hosted_zones: HostedZones,
}

#[derive(Deserialize, Default)]
struct HostedZones {
    #[serde(rename = "HostedZone", default)]
    items: Vec<HostedZone>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostedZone {
    id: String,
    name: String,
    #[serde(default)]
    config: Option<HostedZoneConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostedZoneConfig {
    #[serde(default)]
    private_zone: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListResourceRecordSetsResponse {
    #[serde(default)]
    resource_record_sets: ResourceRecordSets,
}

#[derive(Deserialize, Default)]
struct ResourceRecordSets {
    #[serde(rename = "ResourceRecordSet", default)]
    items: Vec<ResourceRecordSet>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ResourceRecordSet {
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "TTL", default)]
    ttl: Option<u32>,
    #[serde(default)]
    set_identifier: Option<String>,
    #[serde(default)]
    resource_records: Option<ResourceRecords>,
}

#[derive(Deserialize)]
struct ResourceRecords {
    #[serde(rename = "ResourceRecord", default)]
    items: Vec<ResourceRecord>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ResourceRecord {
    value: String,
}

/// Body of both ChangeResourceRecordSets and GetChange responses.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ChangeResponse {
    change_info: ChangeInfo,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ChangeInfo {
    id: String,
    status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ErrorResponse {
    error: AwsError,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsError {
    code: String,
    #[serde(default)]
    message: Option<String>,
}

/// Returned instead of `ErrorResponse` when a change batch is rejected.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InvalidChangeBatch {
    messages: InvalidChangeBatchMessages,
}

#[derive(Deserialize)]
struct InvalidChangeBatchMessages {
    #[serde(rename = "Message", default)]
    items: Vec<String>,
}

#[async_trait]
impl DnsProvider for Route53Provider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        validate_acme_value(value)?;
        let zone_id = self.resolve_zone(fqdn).await?;
        let name = format!("{}.", normalize_name(fqdn));

        let _guard = self.locks.lock(&format!("{zone_id}|{name}")).await;
        // A record set holds every value of the name (e.g. a wildcard and its
        // apex sharing `_acme-challenge`), and UPSERT replaces it whole: the
        // existing values are written back along with the new one.
        let set = match self.fetch_rrset(&zone_id, &name).await? {
            Some(set) if set.contains(value) => return Ok(()),
            Some(mut set) => {
                set.values.push(format!("\"{value}\""));
                set
            }
            None => TxtSet {
                ttl: DEFAULT_TTL,
                values: vec![format!("\"{value}\"")],
            },
        };
        self.change_rrset(&zone_id, "UPSERT", &name, &set).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let zone_id = self.resolve_zone(fqdn).await?;
        let name = format!("{}.", normalize_name(fqdn));

        let _guard = self.locks.lock(&format!("{zone_id}|{name}")).await;
        let set = match self.fetch_rrset(&zone_id, &name).await? {
            Some(set) if set.contains(value) => set,
            _ => return Ok(()),
        };
        let remaining: Vec<String> = set
            .values
            .iter()
            .filter(|v| unquote(v) != value)
            .cloned()
            .collect();
        if remaining.is_empty() {
            // DELETE must match the current record set exactly.
            self.change_rrset(&zone_id, "DELETE", &name, &set).await
        } else {
            let rest = TxtSet {
                ttl: set.ttl,
                values: remaining,
            };
            self.change_rrset(&zone_id, "UPSERT", &name, &rest).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Credentials and request of the AWS SigV4 test suite.
    const TEST_ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
    const TEST_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const TEST_DATE: &str = "20150830T123600Z";
    const TEST_SCOPE: SigningScope<'static> = SigningScope {
        region: "us-east-1",
        service: "service",
    };

    fn test_credentials() -> SigningCredentials<'static> {
        SigningCredentials {
            access_key_id: TEST_ACCESS_KEY_ID,
            secret_access_key: TEST_SECRET,
            session_token: None,
        }
    }

    fn authorization(headers: &[(&'static str, String)]) -> String {
        headers
            .iter()
            .find(|(n, _)| *n == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap()
    }

    #[test]
    fn sigv4_matches_aws_get_vanilla_vector() {
        let url = Url::parse("https://example.amazonaws.com/").unwrap();
        let headers = sign_v4(
            &test_credentials(),
            &TEST_SCOPE,
            "GET",
            &url,
            b"",
            TEST_DATE,
        );
        assert_eq!(
            authorization(&headers),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn sigv4_matches_aws_get_vanilla_query_order_vector() {
        let query = canonical_query(&[("Param2", "value2"), ("Param1", "value1")]);
        assert_eq!(query, "Param1=value1&Param2=value2");
        let url = Url::parse(&format!("https://example.amazonaws.com/?{query}")).unwrap();
        let headers = sign_v4(
            &test_credentials(),
            &TEST_SCOPE,
            "GET",
            &url,
            b"",
            TEST_DATE,
        );
        assert!(
            authorization(&headers).ends_with(
                "Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
            ),
            "{headers:?}"
        );
    }

    #[test]
    fn sigv4_signs_session_token() {
        let credentials = SigningCredentials {
            session_token: Some("session"),
            ..test_credentials()
        };
        let url = Url::parse("https://example.amazonaws.com/").unwrap();
        let headers = sign_v4(&credentials, &TEST_SCOPE, "GET", &url, b"", TEST_DATE);
        assert!(headers.contains(&("x-amz-security-token", "session".to_string())));
        assert!(
            authorization(&headers).contains("SignedHeaders=host;x-amz-date;x-amz-security-token")
        );
    }

    #[test]
    fn canonical_query_encodes_reserved_characters() {
        assert_eq!(
            canonical_query(&[("name", "a b*.example.com.")]),
            "name=a%20b%2A.example.com."
        );
    }

    #[test]
    fn host_header_keeps_non_default_port() {
        let url = Url::parse("http://127.0.0.1:8080/x").unwrap();
        assert_eq!(host_header(&url), "127.0.0.1:8080");
        let url = Url::parse("https://route53.amazonaws.com/x").unwrap();
        assert_eq!(host_header(&url), "route53.amazonaws.com");
    }

    #[test]
    fn amz_date_has_sigv4_format() {
        let date = amz_date_now();
        assert_eq!(date.len(), 16, "{date}");
        assert_eq!(&date[8..9], "T");
        assert!(date.ends_with('Z'));
    }

    #[test]
    fn with_api_base_rejects_non_https() {
        let cfg = Route53Config::new("id", "secret");
        assert!(cfg.with_api_base("http://evil.example").is_err());
    }

    #[test]
    fn with_api_base_accepts_localhost_for_tests() {
        let cfg = Route53Config::new("id", "secret");
        assert!(cfg.with_api_base("http://localhost:8080").is_ok());
    }

    #[test]
    fn with_hosted_zone_id_strips_prefix_and_rejects_path_tricks() {
        let cfg = Route53Config::new("id", "secret")
            .with_hosted_zone_id("/hostedzone/Z123ABC")
            .unwrap();
        assert_eq!(cfg.hosted_zone_id.as_deref(), Some("Z123ABC"));
        assert!(Route53Config::new("id", "secret")
            .with_hosted_zone_id("Z1/../x")
            .is_err());
        assert!(Route53Config::new("id", "secret")
            .with_hosted_zone_id("")
            .is_err());
    }

    #[test]
    fn change_batch_escapes_values() {
        let set = TxtSet {
            ttl: 60,
            values: vec!["\"a<b&c\"".to_string()],
        };
        let xml = change_batch_xml("UPSERT", "_acme-challenge.example.com.", &set);
        assert!(
            xml.contains("<Value>&quot;a&lt;b&amp;c&quot;</Value>"),
            "{xml}"
        );
        assert!(xml.contains("<TTL>60</TTL>"), "{xml}");
    }

    #[test]
    fn auth_error_codes_map_to_auth() {
        let body = "<ErrorResponse><Error><Type>Sender</Type>\
                    <Code>SignatureDoesNotMatch</Code><Message>bad</Message></Error>\
                    <RequestId>1</RequestId></ErrorResponse>";
        let err = map_error("GET", "/x", reqwest::StatusCode::FORBIDDEN, body);
        assert!(matches!(err, DnsError::Auth(_)), "{err:?}");
    }

    #[test]
    fn invalid_change_batch_is_parsed() {
        let body = "<InvalidChangeBatch><Messages><Message>nope</Message></Messages>\
                    </InvalidChangeBatch>";
        let err = map_error("POST", "/x", reqwest::StatusCode::BAD_REQUEST, body);
        let msg = err.to_string();
        assert!(msg.contains("InvalidChangeBatch: nope"), "{msg}");
    }

    #[test]
    fn unquote_strips_surrounding_quotes() {
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("abc"), "abc");
    }
}

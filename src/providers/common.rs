use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use percent_encoding::{utf8_percent_encode, AsciiSet, PercentEncode, CONTROLS};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use url::Url;

use crate::error::DnsError;

const MAX_ERROR_BODY: usize = 512;

/// Throttled (429) and unavailable (503) responses are retried, up to this
/// many attempts in total.
const MAX_ATTEMPTS: u32 = 3;
/// Longest `Retry-After` honoured. A server asking for more is not retried:
/// the response is returned as is, so its error surfaces with the delay.
const MAX_RETRY_WAIT: Duration = Duration::from_secs(10);
/// Wait before the first retry when the server gives no usable
/// `Retry-After`, doubled on each further retry.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// `send()` with bounded retries on transient responses.
///
/// A 429 means the request was not processed, so it is retried whatever the
/// method. A 503 is only retried for idempotent methods: a POST may have been
/// applied before the server gave up, and replaying it could create a
/// duplicate record. The last response is returned unchanged, so callers keep
/// mapping errors as before.
pub(crate) trait SendRetrying {
    fn send_retrying(
        self,
    ) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> + Send;
}

impl SendRetrying for reqwest::RequestBuilder {
    async fn send_retrying(self) -> Result<reqwest::Response, reqwest::Error> {
        let method = self
            .try_clone()
            .and_then(|b| b.build().ok())
            .map(|r| r.method().clone());
        let mut request = self;
        let mut attempt = 1;
        loop {
            // A builder whose body cannot be cloned (a stream) is sent once.
            let next = request.try_clone();
            let response = request.send().await?;
            let (Some(next), Some(method)) = (next, method.as_ref()) else {
                return Ok(response);
            };
            if attempt >= MAX_ATTEMPTS {
                return Ok(response);
            }
            let Some(wait) = retry_delay(method, response.status(), response.headers(), attempt)
            else {
                return Ok(response);
            };
            tokio::time::sleep(wait).await;
            request = next;
            attempt += 1;
        }
    }
}

/// How long to wait before retrying after `attempt` (1-based) got `status`,
/// or `None` when the response must be returned as is.
fn retry_delay(
    method: &reqwest::Method,
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    attempt: u32,
) -> Option<Duration> {
    let retryable = match status {
        reqwest::StatusCode::TOO_MANY_REQUESTS => true,
        reqwest::StatusCode::SERVICE_UNAVAILABLE => method.is_idempotent(),
        _ => false,
    };
    if !retryable {
        return None;
    }
    // Only the delay-seconds form is read; an HTTP-date falls back to backoff.
    let retry_after = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    match retry_after {
        Some(wait) if wait > MAX_RETRY_WAIT => None,
        Some(wait) => Some(wait),
        None => Some(RETRY_BACKOFF * 2u32.pow(attempt - 1)),
    }
}

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

pub(crate) fn encode_path(segment: &str) -> PercentEncode<'_> {
    utf8_percent_encode(segment, PATH_SEGMENT)
}

/// Serializes operations sharing the same key, in-process. Prevents the
/// GET → merge → PUT race when multiple challenges target the same FQDN.
///
/// The lock table is shared by every instance, so two providers built from
/// separate configs (e.g. one solver per certificate) still serialize on the
/// same record. Each instance namespaces its keys by provider, so unrelated
/// providers never wait on each other. Does not protect against concurrent
/// writers in different processes.
pub(crate) struct KeyedMutex {
    namespace: &'static str,
}

type LockTable = StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>;

fn lock_table() -> &'static LockTable {
    static TABLE: OnceLock<LockTable> = OnceLock::new();
    TABLE.get_or_init(Default::default)
}

impl KeyedMutex {
    pub(crate) fn new(namespace: &'static str) -> Self {
        Self { namespace }
    }

    pub(crate) async fn lock(&self, key: &str) -> OwnedMutexGuard<()> {
        let entry = {
            let mut map = lock_table().lock().unwrap_or_else(|e| e.into_inner());
            // Drop entries nobody holds or waits on, so the table does not
            // grow with every name ever locked.
            map.retain(|_, m| Arc::strong_count(m) > 1);
            map.entry(format!("{}|{key}", self.namespace))
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        entry.lock_owned().await
    }
}

/// ACME DNS-01 challenge tokens are SHA-256(key authorization) base64url-encoded:
/// 43 ASCII chars (`[A-Za-z0-9_-]`). Reject anything else to avoid injecting
/// arbitrary content into a TXT record.
pub(crate) fn validate_acme_value(value: &str) -> Result<(), DnsError> {
    if value.is_empty() || value.len() > 128 {
        return Err(DnsError::Other(format!(
            "invalid ACME value length: {}",
            value.len()
        )));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(DnsError::Other(
            "ACME value must be base64url (A-Z a-z 0-9 - _)".into(),
        ));
    }
    Ok(())
}

/// Same as `validate_fqdn`, but also requires the zone to contain at least one
/// dot — a single-label "zone" (e.g. `localhost`) is almost certainly a misuse.
pub(crate) fn validate_zone(zone: &str) -> Result<(), DnsError> {
    validate_fqdn(zone)?;
    let trimmed = zone.trim_end_matches('.');
    if !trimmed.contains('.') {
        return Err(DnsError::Other(format!(
            "zone must have at least two labels, got {zone}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_fqdn(fqdn: &str) -> Result<(), DnsError> {
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
        // Letters, digits, hyphen and underscore (`_acme-challenge`); IDNs
        // arrive as punycode. Anything else (`&`, `=`, `?`, `/`, spaces) has
        // no place in a hostname and could alter the API URLs built from it.
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(DnsError::Other(format!("invalid character in {fqdn}")));
        }
    }
    Ok(())
}

pub(crate) fn relative_name(fqdn: &str, zone: &str) -> Result<String, DnsError> {
    let fqdn = fqdn.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if fqdn == zone {
        return Ok("@".to_string());
    }
    let suffix = format!(".{zone}");
    fqdn.strip_suffix(&suffix)
        .map(str::to_string)
        .ok_or_else(|| DnsError::Other(format!("fqdn {fqdn} is not within zone {zone}")))
}

pub(crate) fn validate_https_base(base: &str, provider: &str) -> Result<(), DnsError> {
    let parsed = Url::parse(base)
        .map_err(|_| DnsError::Other(format!("{provider} api_base is not a valid URL: {base}")))?;
    let scheme_ok = parsed.scheme() == "https"
        || (parsed.scheme() == "http"
            && matches!(
                parsed.host_str(),
                Some("localhost") | Some("127.0.0.1") | Some("::1")
            ));
    if !scheme_ok {
        return Err(DnsError::Other(format!(
            "{provider} api_base must use https:// (got {base})"
        )));
    }
    Ok(())
}

pub(crate) async fn api_error(
    provider: &str,
    method: &str,
    path: String,
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> DnsError {
    let text = truncate_error_body(response.text().await.unwrap_or_default());
    DnsError::Api(format!(
        "{provider} {method} {path} returned {status}: {text}"
    ))
}

/// Caps a provider-supplied error text so a large body cannot flood logs.
pub(crate) fn truncate_error_body(raw: String) -> String {
    if raw.len() <= MAX_ERROR_BODY {
        return raw;
    }
    let mut cut = MAX_ERROR_BODY;
    while cut > 0 && !raw.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut truncated = raw[..cut].to_string();
    truncated.push_str("…(truncated)");
    truncated
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn relative_name_strips_zone_suffix() {
        assert_eq!(
            relative_name("_acme-challenge.kemeter.app", "kemeter.app").unwrap(),
            "_acme-challenge"
        );
    }

    #[test]
    fn relative_name_handles_nested_subdomain() {
        assert_eq!(
            relative_name("_acme-challenge.api.kemeter.app", "kemeter.app").unwrap(),
            "_acme-challenge.api"
        );
    }

    #[test]
    fn relative_name_returns_at_for_apex() {
        assert_eq!(relative_name("kemeter.app", "kemeter.app").unwrap(), "@");
    }

    #[test]
    fn relative_name_ignores_trailing_dot() {
        assert_eq!(
            relative_name("_acme-challenge.kemeter.app.", "kemeter.app.").unwrap(),
            "_acme-challenge"
        );
    }

    #[test]
    fn relative_name_rejects_fqdn_outside_zone() {
        assert!(relative_name("foo.other.com", "kemeter.app").is_err());
    }

    #[test]
    fn validate_acme_value_accepts_base64url() {
        assert!(validate_acme_value("abcDEF123-_").is_ok());
    }

    #[test]
    fn validate_acme_value_rejects_empty_and_invalid() {
        assert!(validate_acme_value("").is_err());
        assert!(validate_acme_value("abc def").is_err());
        assert!(validate_acme_value("abc=").is_err());
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
    fn validate_fqdn_rejects_url_metacharacters() {
        for fqdn in [
            "_acme-challenge.x&per_page=1.com",
            "foo=bar.com",
            "foo?.bar.com",
            "foo/bar.com",
            "foo bar.com",
            "*.bar.com",
        ] {
            assert!(validate_fqdn(fqdn).is_err(), "{fqdn} must be rejected");
        }
    }

    #[test]
    fn validate_fqdn_accepts_punycode() {
        assert!(validate_fqdn("_acme-challenge.xn--bcher-kva.example").is_ok());
    }

    #[test]
    fn validate_https_base_rejects_http() {
        assert!(validate_https_base("http://evil.example", "test").is_err());
    }

    #[test]
    fn validate_https_base_accepts_https() {
        assert!(validate_https_base("https://api.example.com", "test").is_ok());
    }

    #[test]
    fn validate_https_base_accepts_localhost_for_tests() {
        assert!(validate_https_base("http://localhost:8080", "test").is_ok());
    }

    #[test]
    fn validate_https_base_rejects_localhost_lookalike() {
        assert!(validate_https_base("http://localhost.evil.com", "test").is_err());
    }

    #[test]
    fn validate_https_base_rejects_userinfo_smuggling() {
        assert!(validate_https_base("http://localhost@attacker.com", "test").is_err());
    }

    mod retry {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        /// Answers `failures` with `status` (and `Retry-After: retry_after`),
        /// then 200. Returns the server and the request counter.
        async fn flaky(
            verb: &str,
            status: u16,
            retry_after: Option<&str>,
            failures: usize,
        ) -> (MockServer, Arc<AtomicUsize>) {
            let server = MockServer::start().await;
            let hits = Arc::new(AtomicUsize::new(0));
            let counter = hits.clone();
            let retry_after = retry_after.map(str::to_string);
            Mock::given(method(verb))
                .respond_with(move |_: &Request| {
                    if counter.fetch_add(1, Ordering::SeqCst) < failures {
                        let mut r = ResponseTemplate::new(status);
                        if let Some(v) = &retry_after {
                            r = r.insert_header("retry-after", v.as_str());
                        }
                        r
                    } else {
                        ResponseTemplate::new(200)
                    }
                })
                .mount(&server)
                .await;
            (server, hits)
        }

        #[tokio::test]
        async fn rate_limited_request_is_retried_until_it_succeeds() {
            let (server, hits) = flaky("POST", 429, Some("0"), 2).await;
            let response = reqwest::Client::new()
                .post(server.uri())
                .body("payload")
                .send_retrying()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(hits.load(Ordering::SeqCst), 3);
        }

        #[tokio::test]
        async fn gives_up_after_max_attempts_with_the_last_response() {
            let (server, hits) = flaky("GET", 429, Some("0"), usize::MAX).await;
            let response = reqwest::Client::new()
                .get(server.uri())
                .send_retrying()
                .await
                .unwrap();
            assert_eq!(response.status(), 429);
            assert_eq!(hits.load(Ordering::SeqCst), MAX_ATTEMPTS as usize);
        }

        #[tokio::test]
        async fn unavailable_idempotent_request_is_retried() {
            let (server, hits) = flaky("DELETE", 503, Some("0"), 1).await;
            let response = reqwest::Client::new()
                .delete(server.uri())
                .send_retrying()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(hits.load(Ordering::SeqCst), 2);
        }

        #[tokio::test]
        async fn unavailable_post_is_not_replayed() {
            let (server, hits) = flaky("POST", 503, Some("0"), 1).await;
            let response = reqwest::Client::new()
                .post(server.uri())
                .send_retrying()
                .await
                .unwrap();
            assert_eq!(response.status(), 503);
            assert_eq!(hits.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn retry_after_beyond_the_cap_is_not_waited_for() {
            let (server, hits) = flaky("GET", 429, Some("60"), 1).await;
            let response = reqwest::Client::new()
                .get(server.uri())
                .send_retrying()
                .await
                .unwrap();
            assert_eq!(response.status(), 429);
            assert_eq!(hits.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn other_errors_are_not_retried() {
            let (server, hits) = flaky("GET", 500, None, 1).await;
            let response = reqwest::Client::new()
                .get(server.uri())
                .send_retrying()
                .await
                .unwrap();
            assert_eq!(response.status(), 500);
            assert_eq!(hits.load(Ordering::SeqCst), 1);
        }

        fn headers(retry_after: Option<&str>) -> reqwest::header::HeaderMap {
            let mut h = reqwest::header::HeaderMap::new();
            if let Some(v) = retry_after {
                h.insert(reqwest::header::RETRY_AFTER, v.parse().unwrap());
            }
            h
        }

        #[test]
        fn missing_retry_after_backs_off_exponentially() {
            let get = reqwest::Method::GET;
            let status = reqwest::StatusCode::TOO_MANY_REQUESTS;
            assert_eq!(
                retry_delay(&get, status, &headers(None), 1),
                Some(Duration::from_secs(1))
            );
            assert_eq!(
                retry_delay(&get, status, &headers(None), 2),
                Some(Duration::from_secs(2))
            );
        }

        #[test]
        fn retry_after_date_falls_back_to_backoff() {
            let date = Some("Wed, 21 Oct 2026 07:28:00 GMT");
            assert_eq!(
                retry_delay(
                    &reqwest::Method::GET,
                    reqwest::StatusCode::TOO_MANY_REQUESTS,
                    &headers(date),
                    1
                ),
                Some(RETRY_BACKOFF)
            );
        }

        #[test]
        fn retry_after_seconds_are_honoured() {
            assert_eq!(
                retry_delay(
                    &reqwest::Method::PUT,
                    reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    &headers(Some("4")),
                    1
                ),
                Some(Duration::from_secs(4))
            );
        }
    }

    #[tokio::test]
    async fn keyed_mutex_is_shared_between_instances() {
        let a = KeyedMutex::new("test-shared");
        let b = KeyedMutex::new("test-shared");
        let _held = a.lock("zone|name").await;
        let second = tokio::time::timeout(Duration::from_millis(50), b.lock("zone|name")).await;
        assert!(
            second.is_err(),
            "a second instance must wait on the same key"
        );
    }

    #[tokio::test]
    async fn keyed_mutex_namespaces_do_not_contend() {
        let a = KeyedMutex::new("test-ns-a");
        let b = KeyedMutex::new("test-ns-b");
        let _held = a.lock("zone|name").await;
        let other = tokio::time::timeout(Duration::from_millis(50), b.lock("zone|name")).await;
        assert!(
            other.is_ok(),
            "different namespaces must not block each other"
        );
    }

    #[test]
    fn encode_path_escapes_slash() {
        let s = encode_path("foo/../bar").to_string();
        assert_eq!(s, "foo%2F..%2Fbar");
    }
}

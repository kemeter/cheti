use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use cheti::{DnsError, DnsProvider, GoogleCloudDnsConfig, GoogleCloudDnsProvider};
use data_encoding::BASE64URL_NOPAD;
use ring::signature::{KeyPair, RsaKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const PROJECT: &str = "my-project";
const CLIENT_EMAIL: &str = "dns-solver@my-project.iam.gserviceaccount.com";
const MANAGED_ZONE: &str = "example-zone";
const FQDN: &str = "_acme-challenge.example.com";
const NAME: &str = "_acme-challenge.example.com.";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const ZONES_PATH: &str = "/projects/my-project/managedZones";
const RRSETS_PATH: &str = "/projects/my-project/managedZones/example-zone/rrsets";
const CHANGES_PATH: &str = "/projects/my-project/managedZones/example-zone/changes";
const ACCESS_TOKEN: &str = "ya29.test-access-token";
const AUTH: &str = "Bearer ya29.test-access-token";

/// Throwaway RSA key, generated once per test run. Never a real credential.
fn test_key() -> &'static (String, Vec<u8>) {
    static KEY: OnceLock<(String, Vec<u8>)> = OnceLock::new();
    KEY.get_or_init(|| {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        (key.serialize_pem(), key.serialize_der())
    })
}

fn key_json(server: &MockServer) -> String {
    json!({
        "type": "service_account",
        "project_id": PROJECT,
        "private_key_id": "0123456789abcdef",
        "private_key": test_key().0,
        "client_email": CLIENT_EMAIL,
        "client_id": "123456789",
        "token_uri": format!("{}/token", server.uri()),
    })
    .to_string()
}

fn build_config(server: &MockServer) -> GoogleCloudDnsConfig {
    GoogleCloudDnsConfig::from_service_account_json(&key_json(server))
        .unwrap()
        .with_api_base(server.uri())
        .unwrap()
}

fn build_provider(server: &MockServer) -> GoogleCloudDnsProvider {
    let config = build_config(server)
        .with_managed_zone(MANAGED_ZONE)
        .unwrap();
    GoogleCloudDnsProvider::new(config).unwrap()
}

async fn mount_token(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(token_response())
        .mount(server)
        .await;
}

fn token_response() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": ACCESS_TOKEN,
        "expires_in": 3599,
        "token_type": "Bearer",
    }))
}

fn rrset(values: &[&str], ttl: u64) -> Value {
    let rrdatas: Vec<String> = values.iter().map(|v| format!("\"{v}\"")).collect();
    json!({
        "kind": "dns#resourceRecordSet",
        "name": NAME,
        "type": "TXT",
        "ttl": ttl,
        "rrdatas": rrdatas,
    })
}

async fn mount_rrset(server: &MockServer, values: &[&str], ttl: u64) {
    let rrsets: Vec<Value> = if values.is_empty() {
        Vec::new()
    } else {
        vec![rrset(values, ttl)]
    };
    Mock::given(method("GET"))
        .and(path(RRSETS_PATH))
        .and(query_param("name", NAME))
        .and(query_param("type", "TXT"))
        .and(header("authorization", AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "rrsets": rrsets })))
        .expect(1)
        .mount(server)
        .await;
}

fn change_done(req: &Request) -> ResponseTemplate {
    let mut body: Value = serde_json::from_slice(&req.body).unwrap();
    body["id"] = json!("1");
    body["status"] = json!("done");
    ResponseTemplate::new(200).set_body_json(body)
}

async fn mount_no_change(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(CHANGES_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(server)
        .await;
}

fn decode_segment(segment: &str) -> Value {
    serde_json::from_slice(&BASE64URL_NOPAD.decode(segment.as_bytes()).unwrap()).unwrap()
}

#[tokio::test]
async fn token_is_exchanged_once_and_cached() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(token_response())
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(RRSETS_PATH))
        .and(header("authorization", AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "rrsets": [] })))
        .expect(2)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
    provider.cleanup(FQDN, OTHER_VALUE).await.unwrap();
}

#[tokio::test]
async fn jwt_assertion_has_expected_claims_and_signature() {
    let server = MockServer::start().await;
    let token_uri = format!("{}/token", server.uri());

    let expected_aud = token_uri.clone();
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .respond_with(move |req: &Request| {
            let form: Vec<(String, String)> = url::form_urlencoded::parse(&req.body)
                .into_owned()
                .collect();
            let field = |name: &str| {
                form.iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
                    .unwrap()
            };
            assert_eq!(
                field("grant_type"),
                "urn:ietf:params:oauth:grant-type:jwt-bearer"
            );

            let assertion = field("assertion");
            let parts: Vec<&str> = assertion.split('.').collect();
            assert_eq!(parts.len(), 3, "{assertion}");

            let header = decode_segment(parts[0]);
            assert_eq!(header["alg"], "RS256");
            assert_eq!(header["typ"], "JWT");
            assert_eq!(header["kid"], "0123456789abcdef");

            let claims = decode_segment(parts[1]);
            assert_eq!(claims["iss"], CLIENT_EMAIL);
            assert_eq!(
                claims["scope"],
                "https://www.googleapis.com/auth/ndev.clouddns.readwrite"
            );
            assert_eq!(claims["aud"], expected_aud.as_str());
            let iat = claims["iat"].as_u64().unwrap();
            let exp = claims["exp"].as_u64().unwrap();
            assert_eq!(exp - iat, 3600);

            let key_pair = RsaKeyPair::from_pkcs8(&test_key().1).unwrap();
            let public_key =
                UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key_pair.public_key());
            let signature = BASE64URL_NOPAD.decode(parts[2].as_bytes()).unwrap();
            let signed = format!("{}.{}", parts[0], parts[1]);
            public_key
                .verify(signed.as_bytes(), &signature)
                .expect("JWT signature must verify with the service account public key");

            token_response()
        })
        .expect(1)
        .mount(&server)
        .await;

    mount_rrset(&server, &[], 0).await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_creates_rrset_when_absent() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_rrset(&server, &[], 0).await;

    Mock::given(method("POST"))
        .and(path(CHANGES_PATH))
        .and(header("authorization", AUTH))
        .respond_with(|req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["deletions"], json!([]), "{body}");
            assert_eq!(
                body["additions"],
                json!([{
                    "name": NAME,
                    "type": "TXT",
                    "ttl": 60,
                    "rrdatas": [format!("\"{VALUE}\"")],
                }]),
                "{body}"
            );
            change_done(req)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_merges_with_existing_values() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_rrset(&server, &[OTHER_VALUE], 300).await;

    Mock::given(method("POST"))
        .and(path(CHANGES_PATH))
        .respond_with(|req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            // The current RRSet is deleted exactly as fetched, so the change
            // is rejected if someone modified it in between.
            assert_eq!(body["deletions"], json!([rrset(&[OTHER_VALUE], 300)]));
            assert_eq!(
                body["additions"],
                json!([{
                    "name": NAME,
                    "type": "TXT",
                    "ttl": 300,
                    "rrdatas": [format!("\"{OTHER_VALUE}\""), format!("\"{VALUE}\"")],
                }]),
                "{body}"
            );
            change_done(req)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_skips_write_when_value_already_present() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_rrset(&server, &[OTHER_VALUE, VALUE], 60).await;
    mount_no_change(&server).await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_polls_pending_change_until_done() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_rrset(&server, &[], 0).await;

    Mock::given(method("POST"))
        .and(path(CHANGES_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": "7", "status": "pending" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{CHANGES_PATH}/7")))
        .and(header("authorization", AUTH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": "7", "status": "done" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_removes_only_its_own_value() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_rrset(&server, &[VALUE, OTHER_VALUE], 60).await;

    Mock::given(method("POST"))
        .and(path(CHANGES_PATH))
        .respond_with(|req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["deletions"], json!([rrset(&[VALUE, OTHER_VALUE], 60)]));
            assert_eq!(
                body["additions"],
                json!([{
                    "name": NAME,
                    "type": "TXT",
                    "ttl": 60,
                    "rrdatas": [format!("\"{OTHER_VALUE}\"")],
                }]),
                "{body}"
            );
            change_done(req)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_of_last_value_deletes_rrset() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_rrset(&server, &[VALUE], 60).await;

    Mock::given(method("POST"))
        .and(path(CHANGES_PATH))
        .respond_with(|req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["deletions"], json!([rrset(&[VALUE], 60)]));
            assert_eq!(body["additions"], json!([]), "{body}");
            change_done(req)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_is_noop_when_rrset_absent() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_rrset(&server, &[], 0).await;
    mount_no_change(&server).await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_is_noop_when_value_absent() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_rrset(&server, &[OTHER_VALUE], 60).await;
    mount_no_change(&server).await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

/// Mounts the rrsets and changes endpoints of `zone` and expects one write.
async fn mount_zone_write(server: &MockServer, zone: &str, name: &str) {
    let base = format!("{ZONES_PATH}/{zone}");
    Mock::given(method("GET"))
        .and(path(format!("{base}/rrsets")))
        .and(query_param("name", name))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "rrsets": [] })))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{base}/changes")))
        .respond_with(change_done)
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn zone_lookup_picks_longest_public_match() {
    let server = MockServer::start().await;
    mount_token(&server).await;

    Mock::given(method("GET"))
        .and(path(ZONES_PATH))
        .and(header("authorization", AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "managedZones": [
                { "name": "example", "dnsName": "example.com.", "visibility": "public" },
                { "name": "sub-example", "dnsName": "sub.example.com.", "visibility": "public" },
                { "name": "other", "dnsName": "other.com.", "visibility": "public" },
                { "name": "notexample", "dnsName": "notexample.com.", "visibility": "public" },
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    mount_zone_write(
        &server,
        "sub-example",
        "_acme-challenge.www.sub.example.com.",
    )
    .await;

    let provider = GoogleCloudDnsProvider::new(build_config(&server)).unwrap();
    provider
        .present("_acme-challenge.www.sub.example.com", VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn zone_lookup_skips_private_zones() {
    let server = MockServer::start().await;
    mount_token(&server).await;

    // The private zone is the longest match, but public resolvers never see
    // it: the public parent zone must be used.
    Mock::given(method("GET"))
        .and(path(ZONES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "managedZones": [
                { "name": "internal", "dnsName": "internal.example.com.", "visibility": "private" },
                { "name": "example", "dnsName": "example.com.", "visibility": "public" },
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    mount_zone_write(&server, "example", "_acme-challenge.internal.example.com.").await;

    let provider = GoogleCloudDnsProvider::new(build_config(&server)).unwrap();
    provider
        .present("_acme-challenge.internal.example.com", VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn zone_lookup_follows_pagination() {
    let server = MockServer::start().await;
    mount_token(&server).await;

    Mock::given(method("GET"))
        .and(path(ZONES_PATH))
        .and(query_param_is_missing("pageToken"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "managedZones": [
                { "name": "other", "dnsName": "other.com.", "visibility": "public" },
            ],
            "nextPageToken": "page-2",
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(ZONES_PATH))
        .and(query_param("pageToken", "page-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "managedZones": [
                { "name": "example", "dnsName": "example.com.", "visibility": "public" },
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    mount_zone_write(&server, "example", NAME).await;

    let provider = GoogleCloudDnsProvider::new(build_config(&server)).unwrap();
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_fails_when_no_zone_matches() {
    let server = MockServer::start().await;
    mount_token(&server).await;

    Mock::given(method("GET"))
        .and(path(ZONES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "managedZones": [
                { "name": "private-example", "dnsName": "example.com.", "visibility": "private" },
            ]
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("{ZONES_PATH}/private-example/changes")))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = GoogleCloudDnsProvider::new(build_config(&server)).unwrap();
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::ZoneNotFound(_)), "{err}");
}

#[tokio::test]
async fn with_project_overrides_key_project() {
    let server = MockServer::start().await;
    mount_token(&server).await;

    Mock::given(method("GET"))
        .and(path(
            "/projects/dns-project/managedZones/example-zone/rrsets",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "rrsets": [] })))
        .expect(1)
        .mount(&server)
        .await;

    let config = build_config(&server)
        .with_project("dns-project")
        .unwrap()
        .with_managed_zone(MANAGED_ZONE)
        .unwrap();
    let provider = GoogleCloudDnsProvider::new(config).unwrap();
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn with_token_uri_overrides_key_token_uri() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/custom-token"))
        .respond_with(token_response())
        .expect(1)
        .mount(&server)
        .await;
    mount_rrset(&server, &[], 0).await;

    let config = build_config(&server)
        .with_token_uri(format!("{}/custom-token", server.uri()))
        .unwrap()
        .with_managed_zone(MANAGED_ZONE)
        .unwrap();
    let provider = GoogleCloudDnsProvider::new(config).unwrap();
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn rejected_assertion_surfaces_as_auth_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Invalid JWT Signature.",
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Auth(_)), "{err:?}");
    assert!(err.to_string().contains("invalid_grant"), "{err}");
}

#[tokio::test]
async fn forbidden_surfaces_as_auth_error() {
    let server = MockServer::start().await;
    mount_token(&server).await;

    Mock::given(method("GET"))
        .and(path(RRSETS_PATH))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": { "code": 403, "message": "Forbidden", "status": "PERMISSION_DENIED" }
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Auth(_)), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("google-cloud-dns"), "{msg}");
    assert!(msg.contains("403"), "{msg}");
}

#[tokio::test]
async fn unauthorized_surfaces_as_auth_error() {
    let server = MockServer::start().await;
    mount_token(&server).await;

    Mock::given(method("GET"))
        .and(path(RRSETS_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": { "code": 401, "message": "Request had invalid authentication credentials." }
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.cleanup(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Auth(_)), "{err:?}");
}

#[tokio::test]
async fn rate_limit_surfaces_explicit_message() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_rrset(&server, &[], 0).await;

    Mock::given(method("POST"))
        .and(path(CHANGES_PATH))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "30")
                .set_body_json(json!({
                    "error": { "code": 429, "message": "Quota exceeded", "status": "RESOURCE_EXHAUSTED" }
                })),
        )
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rate limited"), "{msg}");
    assert!(msg.contains("429"), "{msg}");
    assert!(msg.contains("30"), "{msg}");
}

#[tokio::test]
async fn concurrent_modification_surfaces_conflict() {
    for status in [409, 412] {
        let server = MockServer::start().await;
        mount_token(&server).await;
        mount_rrset(&server, &[OTHER_VALUE], 60).await;

        Mock::given(method("POST"))
            .and(path(CHANGES_PATH))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "error": { "code": status, "message": "conditionNotMet" }
            })))
            .mount(&server)
            .await;

        let provider = build_provider(&server);
        let err = provider.present(FQDN, VALUE).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(&status.to_string()), "{msg}");
        assert!(msg.contains("modified concurrently"), "{msg}");
    }
}

#[tokio::test]
async fn server_error_surfaces_as_api_error() {
    let server = MockServer::start().await;
    mount_token(&server).await;

    Mock::given(method("GET"))
        .and(path(RRSETS_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Api(_)), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("google-cloud-dns"), "{msg}");
    assert!(msg.contains("500"), "{msg}");
}

#[tokio::test]
async fn invalid_acme_value_is_rejected_before_http() {
    let server = MockServer::start().await;

    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, "not valid!").await.unwrap_err();
    assert!(err.to_string().contains("ACME value"), "{err}");
}

#[tokio::test]
async fn concurrent_present_calls_are_serialized() {
    // Without the keyed lock, both calls would read the same RRSet and the
    // second change would drop the first value; the per-name lock makes the
    // second call see the value added by the first and merge with it.
    let server = MockServer::start().await;
    mount_token(&server).await;
    let state = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let in_flight = Arc::new(AtomicUsize::new(0));

    let state_get = state.clone();
    Mock::given(method("GET"))
        .and(path(RRSETS_PATH))
        .respond_with(move |_: &Request| {
            let values = state_get.lock().unwrap().clone();
            let rrsets = if values.is_empty() {
                json!([])
            } else {
                json!([{ "name": NAME, "type": "TXT", "ttl": 60, "rrdatas": values }])
            };
            ResponseTemplate::new(200).set_body_json(json!({ "rrsets": rrsets }))
        })
        .mount(&server)
        .await;

    let state_post = state.clone();
    let in_flight_post = in_flight.clone();
    Mock::given(method("POST"))
        .and(path(CHANGES_PATH))
        .respond_with(move |req: &Request| {
            let concurrent = in_flight_post.fetch_add(1, Ordering::SeqCst);
            assert_eq!(concurrent, 0, "writes must not overlap");
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let mut values = state_post.lock().unwrap();
            let deleted: Vec<String> = body["deletions"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|r| r["rrdatas"].as_array().unwrap().clone())
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            assert_eq!(deleted, *values, "deletion must match the current RRSet");
            std::thread::sleep(Duration::from_millis(50));
            *values = body["additions"][0]["rrdatas"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            in_flight_post.fetch_sub(1, Ordering::SeqCst);
            change_done(req)
        })
        .expect(2)
        .mount(&server)
        .await;

    let provider = Arc::new(build_provider(&server));

    let p1 = provider.clone();
    let p2 = provider.clone();
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move { p1.present(FQDN, VALUE).await }),
        tokio::spawn(async move { p2.present(FQDN, OTHER_VALUE).await }),
    );
    r1.unwrap().unwrap();
    r2.unwrap().unwrap();

    let final_state = state.lock().unwrap().clone();
    assert_eq!(final_state.len(), 2, "got {final_state:?}");
    assert!(final_state.contains(&format!("\"{VALUE}\"")));
    assert!(final_state.contains(&format!("\"{OTHER_VALUE}\"")));
}

#[tokio::test]
async fn from_service_account_file_reads_key() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_rrset(&server, &[], 0).await;

    let dir = std::env::temp_dir().join(format!("cheti-gcdns-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("key.json");
    std::fs::write(&file, key_json(&server)).unwrap();

    let config = GoogleCloudDnsConfig::from_service_account_file(&file)
        .unwrap()
        .with_api_base(server.uri())
        .unwrap()
        .with_managed_zone(MANAGED_ZONE)
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let provider = GoogleCloudDnsProvider::new(config).unwrap();
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

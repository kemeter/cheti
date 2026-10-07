use cheti::{DnsError, DnsProvider, PorkbunConfig, PorkbunProvider};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const FQDN: &str = "_acme-challenge.example.com";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const RETRIEVE_PATH: &str = "/dns/retrieveByNameType/example.com/TXT/_acme-challenge";
const APEX_RETRIEVE_PATH: &str = "/dns/retrieveByNameType/example.com/TXT";
const CREATE_PATH: &str = "/dns/create/example.com";

fn build_provider(server: &MockServer) -> PorkbunProvider {
    let config = PorkbunConfig::new("pk1_test", "sk1_test")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    PorkbunProvider::new(config).unwrap()
}

fn body_of(req: &Request) -> Value {
    serde_json::from_slice(&req.body).unwrap()
}

fn assert_authenticated(req: &Request) {
    let body = body_of(req);
    assert_eq!(body["apikey"], "pk1_test");
    assert_eq!(body["secretapikey"], "sk1_test");
}

fn records_body(records: &[(&str, &str)]) -> Value {
    let records: Vec<Value> = records
        .iter()
        .map(|(id, content)| {
            json!({
                "id": id,
                "name": FQDN,
                "type": "TXT",
                "content": content,
                "ttl": "600",
                "prio": null,
                "notes": null,
            })
        })
        .collect();
    json!({ "status": "SUCCESS", "cloudflare": "disabled", "records": records })
}

async fn mount_existing(server: &MockServer, records: &[(&str, &str)]) {
    let body = records_body(records);
    Mock::given(method("POST"))
        .and(path(RETRIEVE_PATH))
        .respond_with(move |req: &Request| {
            assert_authenticated(req);
            ResponseTemplate::new(200).set_body_json(body.clone())
        })
        .expect(1)
        .mount(server)
        .await;
}

async fn forbid_writes(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(CREATE_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(server)
        .await;
}

#[tokio::test]
async fn present_creates_record_when_absent() {
    let server = MockServer::start().await;
    mount_existing(&server, &[]).await;

    Mock::given(method("POST"))
        .and(path(CREATE_PATH))
        .respond_with(|req: &Request| {
            assert_authenticated(req);
            let body = body_of(req);
            assert_eq!(body["name"], "_acme-challenge");
            assert_eq!(body["type"], "TXT");
            assert_eq!(body["content"], VALUE);
            assert_eq!(body["ttl"], 600);
            ResponseTemplate::new(200).set_body_json(json!({ "status": "SUCCESS", "id": "1001" }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn mixed_case_zone_and_fqdn_are_matched() {
    let server = MockServer::start().await;
    mount_existing(&server, &[]).await;

    Mock::given(method("POST"))
        .and(path(CREATE_PATH))
        .respond_with(|req: &Request| {
            assert_eq!(body_of(req)["name"], "_acme-challenge");
            ResponseTemplate::new(200).set_body_json(json!({ "status": "SUCCESS", "id": "1001" }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let config = PorkbunConfig::new("pk1_test", "sk1_test")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone("Example.COM")
        .unwrap();
    let provider = PorkbunProvider::new(config).unwrap();
    provider
        .present("_acme-challenge.Example.com", VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn present_adds_a_record_next_to_other_values() {
    let server = MockServer::start().await;
    mount_existing(&server, &[("1000", OTHER_VALUE)]).await;

    Mock::given(method("POST"))
        .and(path(CREATE_PATH))
        .respond_with(|req: &Request| {
            assert_eq!(body_of(req)["content"], VALUE);
            ResponseTemplate::new(200).set_body_json(json!({ "status": "SUCCESS", "id": "1001" }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_is_idempotent_when_value_exists() {
    let server = MockServer::start().await;
    mount_existing(&server, &[("1000", VALUE)]).await;
    forbid_writes(&server).await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_matches_quoted_content() {
    let server = MockServer::start().await;
    let quoted = format!("\"{VALUE}\"");
    mount_existing(&server, &[("1000", quoted.as_str())]).await;
    forbid_writes(&server).await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_tolerates_duplicate_record_race() {
    let server = MockServer::start().await;
    mount_existing(&server, &[]).await;

    Mock::given(method("POST"))
        .and(path(CREATE_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "status": "ERROR",
            "code": "DUPLICATE_RECORD",
            "message": "A record with this name, type and content already exists.",
            "existingId": "1000",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_fails_and_rolls_back_when_zone_is_not_served() {
    let server = MockServer::start().await;
    mount_existing(&server, &[]).await;

    Mock::given(method("POST"))
        .and(path(CREATE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "SUCCESS",
            "id": "1001",
            "warnings": ["example.com is delegated to nameservers we do not operate (ns1.example-dns.net), so this change does NOT affect what resolves."],
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/dns/delete/example.com/1001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "SUCCESS" })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Api(_)), "{err}");
    let msg = err.to_string();
    assert!(msg.contains("will not resolve"), "{msg}");
    assert!(msg.contains("ns1.example-dns.net"), "{msg}");
}

#[tokio::test]
async fn present_at_zone_apex_uses_empty_subdomain() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(APEX_RETRIEVE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(records_body(&[])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(CREATE_PATH))
        .respond_with(|req: &Request| {
            assert_eq!(body_of(req)["name"], "");
            ResponseTemplate::new(200).set_body_json(json!({ "status": "SUCCESS", "id": "1001" }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(ZONE, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_deletes_only_the_record_holding_its_value() {
    let server = MockServer::start().await;
    mount_existing(&server, &[("1000", OTHER_VALUE), ("1001", VALUE)]).await;

    Mock::given(method("POST"))
        .and(path("/dns/delete/example.com/1001"))
        .respond_with(|req: &Request| {
            assert_authenticated(req);
            ResponseTemplate::new(200).set_body_json(json!({ "status": "SUCCESS" }))
        })
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/dns/delete/example.com/1000"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_is_noop_when_value_absent() {
    let server = MockServer::start().await;
    mount_existing(&server, &[("1000", OTHER_VALUE)]).await;

    Mock::given(method("POST"))
        .and(path("/dns/delete/example.com/1000"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_tolerates_record_already_gone() {
    let server = MockServer::start().await;
    mount_existing(&server, &[("1001", VALUE)]).await;

    Mock::given(method("POST"))
        .and(path("/dns/delete/example.com/1001"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "status": "ERROR",
            "code": "INVALID_RECORD_ID",
            "message": "Invalid record ID.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn api_access_disabled_surfaces_clear_auth_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(RETRIEVE_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "status": "ERROR",
            "code": "API_ACCESS_DISABLED",
            "message": "Domain is not opted in to API access.",
            "account": "someone",
        })))
        .expect(1)
        .mount(&server)
        .await;
    forbid_writes(&server).await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Auth(_)), "{err}");
    let msg = err.to_string();
    assert!(msg.contains("API access is not enabled"), "{msg}");
    assert!(msg.contains(ZONE), "{msg}");
}

#[tokio::test]
async fn invalid_credentials_surface_as_auth_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(RETRIEVE_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "status": "ERROR",
            "code": "INVALID_API_KEYS_002",
            "message": "Invalid API key. (002)",
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Auth(_)), "{err}");
    let msg = err.to_string();
    assert!(!msg.contains("sk1_test"), "secret must not leak: {msg}");
}

#[tokio::test]
async fn error_status_on_http_200_is_a_failure() {
    let server = MockServer::start().await;
    mount_existing(&server, &[]).await;

    Mock::given(method("POST"))
        .and(path(CREATE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ERROR",
            "code": "ZONE_RECORD_LIMIT",
            "message": "The zone is at the maximum number of DNS records.",
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Api(_)), "{err}");
    let msg = err.to_string();
    assert!(msg.contains("porkbun"), "{msg}");
    assert!(msg.contains("ZONE_RECORD_LIMIT"), "{msg}");
}

#[tokio::test]
async fn rate_limit_surfaces_retry_after() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(RETRIEVE_PATH))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "42")
                .set_body_json(json!({
                    "status": "ERROR",
                    "code": "RATE_LIMIT_EXCEEDED",
                    "message": "Rate limit exceeded.",
                })),
        )
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("429"), "{msg}");
    assert!(msg.contains("42s"), "{msg}");
}

#[tokio::test]
async fn server_error_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(RETRIEVE_PATH))
        .respond_with(ResponseTemplate::new(502).set_body_string("bad gateway"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Api(_)), "{err}");
    let msg = err.to_string();
    assert!(msg.contains("502"), "{msg}");
    assert!(msg.contains("bad gateway"), "{msg}");
}

#[tokio::test]
async fn present_rejects_fqdn_outside_zone() {
    let server = MockServer::start().await;
    forbid_writes(&server).await;

    let provider = build_provider(&server);
    assert!(provider
        .present("_acme-challenge.other.org", VALUE)
        .await
        .is_err());
}

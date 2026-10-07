use std::sync::Arc;
use std::time::Duration;

use cheti::{DesecConfig, DesecProvider, DnsProvider};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const FQDN: &str = "_acme-challenge.example.com";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const RRSET_PATH: &str = "/domains/example.com/rrsets/_acme-challenge/TXT/";
const BULK_PATH: &str = "/domains/example.com/rrsets/";

async fn build_provider(server: &MockServer) -> DesecProvider {
    mount_domain(server, 3600).await;
    let config = DesecConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    DesecProvider::new(config).unwrap()
}

async fn mount_domain(server: &MockServer, minimum_ttl: u32) {
    Mock::given(method("GET"))
        .and(path("/domains/example.com/"))
        .and(header("authorization", "Token test-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "name": ZONE, "minimum_ttl": minimum_ttl })),
        )
        .mount(server)
        .await;
}

fn rrset_body(values: &[&str]) -> Value {
    let records: Vec<String> = values.iter().map(|v| format!("\"{v}\"")).collect();
    json!({
        "subname": "_acme-challenge",
        "name": "_acme-challenge.example.com.",
        "type": "TXT",
        "ttl": 3600,
        "records": records,
    })
}

fn patched_records(req: &Request) -> Vec<String> {
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    let items = body.as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["subname"], "_acme-challenge");
    assert_eq!(items[0]["type"], "TXT");
    items[0]["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn present_creates_rrset_when_absent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .and(header("authorization", "Token test-token"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(BULK_PATH))
        .and(header("authorization", "Token test-token"))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body[0]["ttl"], 3600);
            assert_eq!(patched_records(req), vec![format!("\"{VALUE}\"")]);
            ResponseTemplate::new(200).set_body_json(json!([]))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server).await;
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_merges_with_existing_values() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_body(&[OTHER_VALUE])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(BULK_PATH))
        .respond_with(move |req: &Request| {
            let records = patched_records(req);
            assert_eq!(records.len(), 2);
            assert!(records.contains(&format!("\"{OTHER_VALUE}\"")));
            assert!(records.contains(&format!("\"{VALUE}\"")));
            ResponseTemplate::new(200).set_body_json(json!([]))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server).await;
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_skips_write_when_value_already_present() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_body(&[VALUE])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server).await;
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_resolves_zone_via_owns_qname() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/domains/"))
        .and(query_param("owns_qname", FQDN))
        .and(header("authorization", "Token test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "name": "example.com", "minimum_ttl": 7200 }
        ])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(BULK_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body[0]["ttl"], 7200, "must honour the domain minimum TTL");
            ResponseTemplate::new(200).set_body_json(json!([]))
        })
        .expect(1)
        .mount(&server)
        .await;

    let config = DesecConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap();
    let provider = DesecProvider::new(config).unwrap();
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_fails_when_no_domain_owns_name() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/domains/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let config = DesecConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap();
    let provider = DesecProvider::new(config).unwrap();
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, cheti::DnsError::ZoneNotFound(_)), "{err}");
}

#[tokio::test]
async fn cleanup_deletes_rrset_when_no_values_remain() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_body(&[VALUE])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(BULK_PATH))
        .respond_with(move |req: &Request| {
            assert!(patched_records(req).is_empty(), "empty records deletes");
            ResponseTemplate::new(200).set_body_json(json!([]))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server).await;
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_keeps_other_values() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_body(&[VALUE, OTHER_VALUE])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(BULK_PATH))
        .respond_with(move |req: &Request| {
            assert_eq!(patched_records(req), vec![format!("\"{OTHER_VALUE}\"")]);
            ResponseTemplate::new(200).set_body_json(json!([]))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server).await;
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_is_noop_when_rrset_absent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server).await;
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn rate_limit_surfaces_retry_after() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(BULK_PATH))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "42")
                .set_body_string("Request was throttled."),
        )
        .mount(&server)
        .await;

    let provider = build_provider(&server).await;
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("desec"), "{msg}");
    assert!(msg.contains("429"), "{msg}");
    assert!(msg.contains("42s"), "{msg}");
}

#[tokio::test]
async fn server_error_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let provider = build_provider(&server).await;
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("desec"), "{msg}");
    assert!(msg.contains("500"), "{msg}");
}

#[tokio::test]
async fn invalid_acme_value_is_rejected_before_http() {
    let server = MockServer::start().await;
    let provider = build_provider(&server).await;
    let err = provider.present(FQDN, "not valid!").await.unwrap_err();
    assert!(err.to_string().contains("ACME value"), "{err}");
}

#[tokio::test]
async fn concurrent_present_calls_are_serialized() {
    // Without the keyed lock, both calls would read an empty RRset and each
    // write a single value, the second write overwriting the first.
    let server = MockServer::start().await;
    let state = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    let state_get = state.clone();
    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(move |_: &Request| {
            let records = state_get.lock().unwrap().clone();
            if records.is_empty() {
                ResponseTemplate::new(404)
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "subname": "_acme-challenge",
                    "type": "TXT",
                    "ttl": 3600,
                    "records": records,
                }))
            }
        })
        .mount(&server)
        .await;

    let state_patch = state.clone();
    Mock::given(method("PATCH"))
        .and(path(BULK_PATH))
        .respond_with(move |req: &Request| {
            let records = patched_records(req);
            std::thread::sleep(Duration::from_millis(50));
            *state_patch.lock().unwrap() = records;
            ResponseTemplate::new(200).set_body_json(json!([]))
        })
        .mount(&server)
        .await;

    let provider = Arc::new(build_provider(&server).await);

    let p1 = provider.clone();
    let p2 = provider.clone();
    let v1 = VALUE.to_string();
    let v2 = OTHER_VALUE.to_string();
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move { p1.present(FQDN, &v1).await }),
        tokio::spawn(async move { p2.present(FQDN, &v2).await }),
    );
    r1.unwrap().unwrap();
    r2.unwrap().unwrap();

    let final_state = state.lock().unwrap().clone();
    assert_eq!(final_state.len(), 2, "got {final_state:?}");
    assert!(final_state.contains(&format!("\"{VALUE}\"")));
    assert!(final_state.contains(&format!("\"{OTHER_VALUE}\"")));
}

#[tokio::test]
async fn present_with_zone_honours_minimum_ttl() {
    let server = MockServer::start().await;
    mount_domain(&server, 7200).await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(BULK_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body[0]["ttl"], 7200);
            ResponseTemplate::new(200).set_body_json(json!([]))
        })
        .expect(1)
        .mount(&server)
        .await;

    let config = DesecConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    let provider = DesecProvider::new(config).unwrap();
    provider.present(FQDN, VALUE).await.unwrap();
}

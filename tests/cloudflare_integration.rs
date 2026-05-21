use cheti::{CloudflareConfig, CloudflareProvider, DnsProvider};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const ZONE_ID: &str = "abc123zoneid";
const FQDN: &str = "_acme-challenge.example.com";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";

fn records_path() -> String {
    format!("/zones/{ZONE_ID}/dns_records")
}

fn record_item_path(record_id: &str) -> String {
    format!("/zones/{ZONE_ID}/dns_records/{record_id}")
}

fn cf_ok<T: serde::Serialize>(result: T) -> Value {
    json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": result
    })
}

fn cf_err(code: i64, message: &str) -> Value {
    json!({
        "success": false,
        "errors": [{ "code": code, "message": message }],
        "messages": [],
        "result": null
    })
}

fn build_provider(server: &MockServer) -> CloudflareProvider {
    let config = CloudflareConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone_id(ZONE, ZONE_ID)
        .unwrap();
    CloudflareProvider::new(config).unwrap()
}

#[tokio::test]
async fn present_creates_record_when_absent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(records_path()))
        .and(query_param("type", "TXT"))
        .and(query_param("name", FQDN))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_ok::<Vec<Value>>(vec![])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(records_path()))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["type"], "TXT");
            assert_eq!(body["name"], FQDN);
            // Critical: CF wants the content quoted.
            assert_eq!(body["content"], format!("\"{VALUE}\""));
            assert_eq!(body["ttl"], 60);
            ResponseTemplate::new(200).set_body_json(cf_ok(json!({
                "id": "rec1", "type": "TXT", "name": FQDN, "content": format!("\"{VALUE}\""), "ttl": 60
            })))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_is_idempotent_when_value_already_present() {
    let server = MockServer::start().await;

    // Cloudflare returns the value wrapped in quotes.
    Mock::given(method("GET"))
        .and(path(records_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_ok(json!([
            { "id": "rec1", "content": format!("\"{VALUE}\"") }
        ]))))
        .expect(1)
        .mount(&server)
        .await;

    // No POST should happen.
    Mock::given(method("POST"))
        .and(path(records_path()))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_creates_alongside_existing_other_value() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(records_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_ok(json!([
            { "id": "rec1", "content": format!("\"{OTHER_VALUE}\"") }
        ]))))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(records_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_ok(json!({
            "id": "rec2", "type": "TXT", "name": FQDN, "content": format!("\"{VALUE}\""), "ttl": 60
        }))))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_deletes_matching_record_only() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(records_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_ok(json!([
            { "id": "keep", "content": format!("\"{OTHER_VALUE}\"") },
            { "id": "drop", "content": format!("\"{VALUE}\"") }
        ]))))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(record_item_path("drop")))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_ok(json!({ "id": "drop" }))))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(record_item_path("keep")))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_tolerates_404_on_delete() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(records_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_ok(json!([
            { "id": "gone", "content": format!("\"{VALUE}\"") }
        ]))))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(record_item_path("gone")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn api_error_envelope_surfaces_as_dns_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(records_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_err(7003, "no route")))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("cloudflare"), "{msg}");
}

#[tokio::test]
async fn http_500_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(records_path()))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("cloudflare"), "{msg}");
    assert!(msg.contains("500"), "{msg}");
}

#[tokio::test]
async fn with_zone_only_triggers_zone_id_lookup() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones"))
        .and(query_param("name", ZONE))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_ok(json!([
            { "id": ZONE_ID, "name": ZONE }
        ]))))
        .expect(1) // looked up exactly once (cached after that)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(records_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_ok::<Vec<Value>>(vec![])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(records_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_ok(json!({
            "id": "rec1", "type": "TXT", "name": FQDN, "content": format!("\"{VALUE}\""), "ttl": 60
        }))))
        .mount(&server)
        .await;

    let config = CloudflareConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    let provider = CloudflareProvider::new(config).unwrap();

    // Two calls: the second must hit the cache, not refetch /zones.
    provider.present(FQDN, VALUE).await.unwrap();
    provider.present(FQDN, VALUE).await.unwrap();
}

use std::sync::Arc;
use std::time::Duration;

use cheti::{DnsProvider, InfomaniakConfig, InfomaniakProvider};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const FQDN: &str = "_acme-challenge.example.com";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const RECORDS_PATH: &str = "/2/zones/example.com/records";

fn ik_ok(data: Value) -> Value {
    json!({ "result": "success", "data": data })
}

fn ik_err(code: &str) -> Value {
    json!({
        "result": "error",
        "error": { "code": code, "description": "details" }
    })
}

fn txt_record(id: u64, source: &str, value: &str) -> Value {
    json!({
        "id": id,
        "source": source,
        "type": "TXT",
        "ttl": 300,
        "target": format!("\"{value}\""),
        "updated_at": 1_790_000_000
    })
}

fn build_provider(server: &MockServer) -> InfomaniakProvider {
    let config = InfomaniakConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    InfomaniakProvider::new(config).unwrap()
}

async fn mount_records(server: &MockServer, records: Value) {
    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .and(query_param("filter[types][]", "TXT"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ik_ok(records)))
        .mount(server)
        .await;
}

fn created(req: &Request) -> ResponseTemplate {
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    ResponseTemplate::new(200).set_body_json(ik_ok(json!({
        "id": 99,
        "source": body["source"],
        "type": "TXT",
        "ttl": body["ttl"],
        "target": format!("\"{}\"", body["target"].as_str().unwrap()),
        "updated_at": 1_790_000_000
    })))
}

#[tokio::test]
async fn present_creates_record_when_absent() {
    let server = MockServer::start().await;
    mount_records(&server, json!([])).await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["type"], "TXT");
            assert_eq!(body["source"], "_acme-challenge");
            assert_eq!(body["target"], VALUE);
            assert_eq!(body["ttl"], 300);
            created(req)
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
    mount_records(&server, json!([txt_record(7, "_acme-challenge", VALUE)])).await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_adds_second_value_alongside_existing_one() {
    // Wildcard + apex issuance: two values live on the same name.
    let server = MockServer::start().await;
    mount_records(
        &server,
        json!([
            txt_record(7, "_acme-challenge", OTHER_VALUE),
            txt_record(8, "_acme-challenge.www", VALUE),
        ]),
    )
    .await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["source"], "_acme-challenge");
            assert_eq!(body["target"], VALUE);
            created(req)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_treats_already_exists_as_success() {
    let server = MockServer::start().await;
    mount_records(&server, json!([])).await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(ik_err("dns_record_already_exists")))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_follows_pagination() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "success",
            "data": [txt_record(1, "_acme-challenge", OTHER_VALUE)],
            "total": 2, "page": 1, "pages": 2, "items_per_page": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "success",
            "data": [txt_record(2, "_acme-challenge", VALUE)],
            "total": 2, "page": 2, "pages": 2, "items_per_page": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_resolves_zone_by_walking_up_labels() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2/zones/_acme-challenge.www.example.com"))
        .respond_with(ResponseTemplate::new(404).set_body_json(ik_err("zone_does_not_exists")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/2/zones/www.example.com"))
        .respond_with(ResponseTemplate::new(404).set_body_json(ik_err("zone_does_not_exists")))
        .expect(1)
        .mount(&server)
        .await;

    // Looked up once: `cleanup` reuses the cached zone.
    Mock::given(method("GET"))
        .and(path("/2/zones/example.com"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ik_ok(json!({
            "id": 61022, "fqdn": "example.com", "dnssec": { "is_enabled": false }, "nameservers": []
        }))))
        .expect(1)
        .mount(&server)
        .await;

    mount_records(&server, json!([])).await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["source"], "_acme-challenge.www");
            created(req)
        })
        .expect(1)
        .mount(&server)
        .await;

    let config = InfomaniakConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap();
    let provider = InfomaniakProvider::new(config).unwrap();
    let fqdn = "_acme-challenge.www.example.com";
    provider.present(fqdn, VALUE).await.unwrap();
    provider.cleanup(fqdn, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_fails_when_no_zone_matches() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2/zones/_acme-challenge.example.com"))
        .respond_with(ResponseTemplate::new(404).set_body_json(ik_err("zone_does_not_exists")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/2/zones/example.com"))
        .respond_with(ResponseTemplate::new(404).set_body_json(ik_err("object_not_found")))
        .expect(1)
        .mount(&server)
        .await;

    // The bare TLD is never queried.
    Mock::given(method("GET"))
        .and(path("/2/zones/com"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let config = InfomaniakConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap();
    let provider = InfomaniakProvider::new(config).unwrap();
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, cheti::DnsError::ZoneNotFound(_)), "{err}");
}

#[tokio::test]
async fn cleanup_deletes_only_its_value() {
    let server = MockServer::start().await;
    mount_records(
        &server,
        json!([
            txt_record(7, "_acme-challenge", OTHER_VALUE),
            txt_record(8, "_acme-challenge", VALUE),
        ]),
    )
    .await;

    Mock::given(method("DELETE"))
        .and(path(format!("{RECORDS_PATH}/8")))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ik_ok(json!(true))))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("{RECORDS_PATH}/7")))
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
    mount_records(
        &server,
        json!([txt_record(7, "_acme-challenge", OTHER_VALUE)]),
    )
    .await;

    Mock::given(method("DELETE"))
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
    mount_records(&server, json!([txt_record(8, "_acme-challenge", VALUE)])).await;

    Mock::given(method("DELETE"))
        .and(path(format!("{RECORDS_PATH}/8")))
        .respond_with(ResponseTemplate::new(404).set_body_json(ik_err("object_not_found")))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn error_envelope_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(ik_err("not_authorized")))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("infomaniak"), "{msg}");
    assert!(msg.contains("not_authorized"), "{msg}");
}

#[tokio::test]
async fn http_error_surfaces_as_api_error() {
    let server = MockServer::start().await;
    mount_records(&server, json!([])).await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(ik_err("invalid_dns_record")))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("infomaniak"), "{msg}");
    assert!(msg.contains("400"), "{msg}");
    assert!(msg.contains("invalid_dns_record"), "{msg}");
}

#[tokio::test]
async fn unauthorized_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_json(ik_err("not_authorized")))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.cleanup(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("401"), "{msg}");
}

#[tokio::test]
async fn invalid_acme_value_is_rejected_before_http() {
    let server = MockServer::start().await;
    let provider = build_provider(&server);
    let err = provider.present(FQDN, "not valid!").await.unwrap_err();
    assert!(err.to_string().contains("ACME value"), "{err}");
}

#[tokio::test]
async fn concurrent_present_calls_create_one_record_per_value() {
    let server = MockServer::start().await;
    let state = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));

    let state_get = state.clone();
    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(move |_: &Request| {
            let records = state_get.lock().unwrap().clone();
            ResponseTemplate::new(200).set_body_json(ik_ok(Value::Array(records)))
        })
        .mount(&server)
        .await;

    let state_post = state.clone();
    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let mut records = state_post.lock().unwrap();
            let id = records.len() as u64 + 1;
            let value = body["target"].as_str().unwrap();
            records.push(txt_record(id, "_acme-challenge", value));
            created(req)
        })
        .mount(&server)
        .await;

    let provider = Arc::new(build_provider(&server));
    let p1 = provider.clone();
    let p2 = provider.clone();
    let p3 = provider.clone();
    let (r1, r2, r3) = tokio::join!(
        tokio::spawn(async move { p1.present(FQDN, VALUE).await }),
        tokio::spawn(async move { p2.present(FQDN, OTHER_VALUE).await }),
        tokio::spawn(async move { p3.present(FQDN, VALUE).await }),
    );
    r1.unwrap().unwrap();
    r2.unwrap().unwrap();
    r3.unwrap().unwrap();

    let final_state = state.lock().unwrap().clone();
    assert_eq!(final_state.len(), 2, "got {final_state:?}");
}

#[tokio::test]
async fn mixed_case_zone_override_is_normalized() {
    let server = MockServer::start().await;
    mount_records(&server, json!([])).await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["source"], "_acme-challenge");
            created(req)
        })
        .expect(1)
        .mount(&server)
        .await;

    let config = InfomaniakConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone("Example.COM.")
        .unwrap();
    let provider = InfomaniakProvider::new(config).unwrap();
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn listing_beyond_page_cap_is_an_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "success",
            "data": [],
            "total": 1000, "page": 1, "pages": 1000, "items_per_page": 1
        })))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.cleanup(FQDN, VALUE).await.unwrap_err();
    assert!(err.to_string().contains("pages"), "{err}");
}

use std::sync::Arc;
use std::time::Duration;

use cheti::{DnsProvider, ScalewayConfig, ScalewayProvider};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const FQDN: &str = "_acme-challenge.example.com";
const RNAME: &str = "_acme-challenge";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const RECORDS_PATH: &str = "/domain/v2beta1/dns-zones/example.com/records";

fn build_provider(server: &MockServer) -> ScalewayProvider {
    let config = ScalewayConfig::new("test-secret")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    ScalewayProvider::new(config).unwrap()
}

fn set_change_records(body: &Value) -> &Vec<Value> {
    let changes = body["changes"].as_array().expect("changes array");
    assert_eq!(changes.len(), 1);
    changes[0]["set"]["records"]
        .as_array()
        .expect("set.records array")
}

fn is_delete_change(body: &Value) -> bool {
    body["changes"]
        .as_array()
        .and_then(|c| c.first())
        .map(|c| c.get("delete").is_some())
        .unwrap_or(false)
}

#[tokio::test]
async fn present_creates_record_when_absent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .and(query_param("name", RNAME))
        .and(query_param("type", "TXT"))
        .and(header("x-auth-token", "test-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "records": [] })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(RECORDS_PATH))
        .and(header("x-auth-token", "test-secret"))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let records = set_change_records(&body);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["data"], VALUE);
            assert_eq!(records[0]["name"], RNAME);
            assert_eq!(records[0]["type"], "TXT");
            ResponseTemplate::new(200)
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

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                { "type": "TXT", "data": OTHER_VALUE }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let records = set_change_records(&body);
            assert_eq!(records.len(), 2);
            let datas: Vec<&str> =
                records.iter().map(|r| r["data"].as_str().unwrap()).collect();
            assert!(datas.contains(&OTHER_VALUE));
            assert!(datas.contains(&VALUE));
            ResponseTemplate::new(200)
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

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                { "type": "TXT", "data": VALUE }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let records = set_change_records(&body);
            assert_eq!(records.len(), 1, "must not duplicate value");
            assert_eq!(records[0]["data"], VALUE);
            ResponseTemplate::new(200)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_deletes_record_when_no_values_remain() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                { "type": "TXT", "data": VALUE }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert!(is_delete_change(&body), "expected delete change, got {body}");
            ResponseTemplate::new(200)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_keeps_other_values_via_set() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                { "type": "TXT", "data": VALUE },
                { "type": "TXT", "data": OTHER_VALUE }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert!(!is_delete_change(&body), "expected set, got delete");
            let records = set_change_records(&body);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["data"], OTHER_VALUE);
            ResponseTemplate::new(200)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_tolerates_404_on_delete_patch() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                { "type": "TXT", "data": VALUE }
            ]
        })))
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn server_error_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("scaleway"), "{msg}");
    assert!(msg.contains("500"), "{msg}");
}

#[tokio::test]
async fn concurrent_present_calls_are_serialized() {
    let server = MockServer::start().await;
    let state = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    let state_get = state.clone();
    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(move |_: &Request| {
            let values = state_get.lock().unwrap().clone();
            let records: Vec<Value> = values
                .into_iter()
                .map(|v| json!({ "type": "TXT", "data": v }))
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({ "records": records }))
        })
        .mount(&server)
        .await;

    let state_patch = state.clone();
    Mock::given(method("PATCH"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let records = set_change_records(&body);
            let values: Vec<String> = records
                .iter()
                .map(|r| r["data"].as_str().unwrap().to_string())
                .collect();
            std::thread::sleep(Duration::from_millis(50));
            *state_patch.lock().unwrap() = values;
            ResponseTemplate::new(200)
        })
        .mount(&server)
        .await;

    let provider = Arc::new(build_provider(&server));

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
    assert_eq!(
        final_state.len(),
        2,
        "both values should be present, got {final_state:?}"
    );
    assert!(final_state.contains(&VALUE.to_string()));
    assert!(final_state.contains(&OTHER_VALUE.to_string()));
}

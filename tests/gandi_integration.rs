use std::sync::Arc;
use std::time::Duration;

use cheti::{DnsProvider, GandiConfig, GandiProvider};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const FQDN: &str = "_acme-challenge.example.com";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const RECORD_PATH: &str = "/livedns/domains/example.com/records/_acme-challenge/TXT";

fn build_provider(server: &MockServer) -> GandiProvider {
    let config = GandiConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    GandiProvider::new(config).unwrap()
}

#[tokio::test]
async fn present_creates_record_when_absent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORD_PATH))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(RECORD_PATH))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["rrset_values"], json!([VALUE]));
            assert_eq!(body["rrset_ttl"], 300);
            ResponseTemplate::new(201)
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
        .and(path(RECORD_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rrset_ttl": 300,
            "rrset_values": [OTHER_VALUE]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(RECORD_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let values = body["rrset_values"].as_array().unwrap();
            assert_eq!(values.len(), 2);
            assert!(values.iter().any(|v| v == OTHER_VALUE));
            assert!(values.iter().any(|v| v == VALUE));
            ResponseTemplate::new(201)
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
        .and(path(RECORD_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rrset_ttl": 300,
            "rrset_values": [VALUE]
        })))
        .expect(1)
        .mount(&server)
        .await;

    // PUT is still issued (Gandi is the source of truth), but with no growth.
    Mock::given(method("PUT"))
        .and(path(RECORD_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let values = body["rrset_values"].as_array().unwrap();
            assert_eq!(values.len(), 1, "must not duplicate value");
            assert_eq!(values[0], VALUE);
            ResponseTemplate::new(201)
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
        .and(path(RECORD_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rrset_ttl": 300,
            "rrset_values": [VALUE]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(RECORD_PATH))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(RECORD_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_keeps_other_values_via_put() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORD_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rrset_ttl": 300,
            "rrset_values": [VALUE, OTHER_VALUE]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(RECORD_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let values = body["rrset_values"].as_array().unwrap();
            assert_eq!(values.len(), 1);
            assert_eq!(values[0], OTHER_VALUE);
            ResponseTemplate::new(201)
        })
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(RECORD_PATH))
        .respond_with(ResponseTemplate::new(204))
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
        .and(path(RECORD_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rrset_ttl": 300,
            "rrset_values": [VALUE]
        })))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(RECORD_PATH))
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
        .and(path(RECORD_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("gandi"), "{msg}");
    assert!(msg.contains("500"), "{msg}");
}

#[tokio::test]
async fn invalid_acme_value_is_rejected_before_http() {
    let server = MockServer::start().await;
    // No mocks: any request would 404 from wiremock with an unmatched-route panic.
    let provider = build_provider(&server);
    let err = provider.present(FQDN, "not valid!").await.unwrap_err();
    assert!(err.to_string().contains("ACME value"), "{err}");
}

#[tokio::test]
async fn concurrent_present_calls_are_serialized() {
    // If KeyedMutex didn't serialize, both calls would GET concurrently and each
    // PUT [value] — the second PUT overwriting the first. The server here only
    // returns the value AFTER a PUT lands, so observing both values in the final
    // state requires GET-merge-PUT to run twice serially.
    let server = MockServer::start().await;
    let state = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    let state_get = state.clone();
    Mock::given(method("GET"))
        .and(path(RECORD_PATH))
        .respond_with(move |_: &Request| {
            let values = state_get.lock().unwrap().clone();
            if values.is_empty() {
                ResponseTemplate::new(404)
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "rrset_ttl": 300,
                    "rrset_values": values,
                }))
            }
        })
        .mount(&server)
        .await;

    let state_put = state.clone();
    Mock::given(method("PUT"))
        .and(path(RECORD_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let values: Vec<String> = body["rrset_values"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            // Simulate latency between read and write to widen the race window.
            std::thread::sleep(Duration::from_millis(50));
            *state_put.lock().unwrap() = values;
            ResponseTemplate::new(201)
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

use std::sync::Arc;
use std::time::Duration;

use cheti::{DnsProvider, OvhConfig, OvhProvider};
use serde_json::{json, Value};
use wiremock::matchers::{header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const FQDN: &str = "_acme-challenge.example.com";
const SUB_DOMAIN: &str = "_acme-challenge";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const RECORDS_PATH: &str = "/domain/zone/example.com/record";
const REFRESH_PATH: &str = "/domain/zone/example.com/refresh";

fn build_provider(server: &MockServer) -> OvhProvider {
    let config = OvhConfig::new("test-app-key", "test-app-secret", "test-consumer-key")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    OvhProvider::new(config).unwrap()
}

fn item_path(id: u64) -> String {
    format!("/domain/zone/example.com/record/{id}")
}

/// Every OVH request must carry these four headers. We assert presence on each
/// mock so we know the signing path executed.
fn ovh_signed() -> wiremock::MockBuilder {
    Mock::given(header_exists("x-ovh-application"))
        .and(header_exists("x-ovh-consumer"))
        .and(header_exists("x-ovh-timestamp"))
        .and(header_exists("x-ovh-signature"))
}

#[tokio::test]
async fn present_creates_record_when_absent() {
    let server = MockServer::start().await;

    ovh_signed()
        .and(method("GET"))
        .and(path(RECORDS_PATH))
        .and(query_param("fieldType", "TXT"))
        .and(query_param("subDomain", SUB_DOMAIN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["fieldType"], "TXT");
            assert_eq!(body["subDomain"], SUB_DOMAIN);
            assert_eq!(body["target"], VALUE);
            ResponseTemplate::new(200).set_body_json(json!({
                "id": 42, "fieldType": "TXT", "subDomain": SUB_DOMAIN, "target": VALUE, "ttl": 60, "zone": ZONE
            }))
        })
        .expect(1)
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("POST"))
        .and(path(REFRESH_PATH))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_is_idempotent_when_value_already_present() {
    let server = MockServer::start().await;

    ovh_signed()
        .and(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([7u64])))
        .expect(1)
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("GET"))
        .and(path(item_path(7)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 7, "target": format!("\"{VALUE}\"")
        })))
        .expect(1)
        .mount(&server)
        .await;

    // No POST to create, no refresh: the value is already there.
    ovh_signed()
        .and(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("POST"))
        .and(path(REFRESH_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_creates_when_other_values_exist() {
    let server = MockServer::start().await;

    ovh_signed()
        .and(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([11u64])))
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("GET"))
        .and(path(item_path(11)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 11, "target": OTHER_VALUE
        })))
        .expect(1)
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 12, "fieldType": "TXT", "subDomain": SUB_DOMAIN, "target": VALUE, "ttl": 60, "zone": ZONE
        })))
        .expect(1)
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("POST"))
        .and(path(REFRESH_PATH))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_deletes_only_matching_record() {
    let server = MockServer::start().await;

    ovh_signed()
        .and(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([21u64, 22u64])))
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("GET"))
        .and(path(item_path(21)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 21, "target": OTHER_VALUE
        })))
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("GET"))
        .and(path(item_path(22)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 22, "target": VALUE
        })))
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("DELETE"))
        .and(path(item_path(22)))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    // Must NOT delete the non-matching record.
    ovh_signed()
        .and(method("DELETE"))
        .and(path(item_path(21)))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("POST"))
        .and(path(REFRESH_PATH))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_skips_refresh_when_nothing_to_delete() {
    let server = MockServer::start().await;

    ovh_signed()
        .and(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("POST"))
        .and(path(REFRESH_PATH))
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

    ovh_signed()
        .and(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([99u64])))
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("GET"))
        .and(path(item_path(99)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 99, "target": VALUE
        })))
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("DELETE"))
        .and(path(item_path(99)))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("POST"))
        .and(path(REFRESH_PATH))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn server_error_surfaces_as_api_error() {
    let server = MockServer::start().await;

    ovh_signed()
        .and(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("ovh"), "{msg}");
    assert!(msg.contains("500"), "{msg}");
}

#[tokio::test]
async fn concurrent_present_calls_are_serialized() {
    let server = MockServer::start().await;
    // Records stored in a shared mutable slice; the API endpoints read/mutate it.
    let records: Arc<std::sync::Mutex<Vec<(u64, String)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let next_id = Arc::new(std::sync::Mutex::new(100u64));

    let r_list = records.clone();
    ovh_signed()
        .and(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(move |_: &Request| {
            let ids: Vec<u64> = r_list.lock().unwrap().iter().map(|(id, _)| *id).collect();
            ResponseTemplate::new(200).set_body_json(serde_json::json!(ids))
        })
        .mount(&server)
        .await;

    let r_get = records.clone();
    ovh_signed()
        .and(method("GET"))
        .and(wiremock::matchers::path_regex(
            r"^/domain/zone/example\.com/record/\d+$",
        ))
        .respond_with(move |req: &Request| {
            let id_str = req.url.path().rsplit('/').next().unwrap();
            let id: u64 = id_str.parse().unwrap();
            let guard = r_get.lock().unwrap();
            let entry = guard.iter().find(|(rid, _)| *rid == id).unwrap();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": entry.0, "target": entry.1
            }))
        })
        .mount(&server)
        .await;

    let r_post = records.clone();
    let id_post = next_id.clone();
    ovh_signed()
        .and(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let target = body["target"].as_str().unwrap().to_string();
            // simulate work between the GET-list and the POST-create
            std::thread::sleep(Duration::from_millis(50));
            let mut id_guard = id_post.lock().unwrap();
            let id = *id_guard;
            *id_guard += 1;
            r_post.lock().unwrap().push((id, target));
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": id
            }))
        })
        .mount(&server)
        .await;

    ovh_signed()
        .and(method("POST"))
        .and(path(REFRESH_PATH))
        .respond_with(ResponseTemplate::new(200))
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

    let final_state = records.lock().unwrap().clone();
    assert_eq!(
        final_state.len(),
        2,
        "both values should land as distinct records, got {final_state:?}"
    );
    let values: Vec<&str> = final_state.iter().map(|(_, t)| t.as_str()).collect();
    assert!(values.contains(&VALUE));
    assert!(values.contains(&OTHER_VALUE));
}

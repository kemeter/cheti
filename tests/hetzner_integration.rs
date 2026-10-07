use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cheti::{DnsProvider, HetznerConfig, HetznerProvider};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const FQDN: &str = "_acme-challenge.example.com";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const RRSET_PATH: &str = "/zones/example.com/rrsets/_acme-challenge/TXT";
const ADD_PATH: &str = "/zones/example.com/rrsets/_acme-challenge/TXT/actions/add_records";
const REMOVE_PATH: &str = "/zones/example.com/rrsets/_acme-challenge/TXT/actions/remove_records";
const AUTH: &str = "Bearer test-token";

fn build_provider(server: &MockServer) -> HetznerProvider {
    let config = HetznerConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    HetznerProvider::new(config).unwrap()
}

fn rrset_body(values: &[&str]) -> Value {
    let records: Vec<Value> = values
        .iter()
        .map(|v| json!({ "value": format!("\"{v}\""), "comment": "" }))
        .collect();
    json!({
        "rrset": {
            "id": "_acme-challenge/TXT",
            "name": "_acme-challenge",
            "type": "TXT",
            "ttl": 60,
            "labels": {},
            "protection": { "change": false },
            "records": records,
            "zone": 42,
        }
    })
}

fn not_found() -> ResponseTemplate {
    ResponseTemplate::new(404).set_body_json(json!({
        "error": { "code": "not_found", "message": "rrset not found", "details": null }
    }))
}

fn action_body(id: u64, command: &str, status: &str) -> Value {
    json!({
        "action": {
            "id": id,
            "command": command,
            "status": status,
            "progress": if status == "running" { 50 } else { 100 },
            "started": "2026-01-01T00:00:00Z",
            "finished": if status == "running" { Value::Null } else { json!("2026-01-01T00:00:01Z") },
            "resources": [{ "id": 42, "type": "zone" }],
            "error": Value::Null,
        }
    })
}

fn written_values(req: &Request) -> Vec<String> {
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    body["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["value"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn present_creates_rrset_when_absent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .and(header("authorization", AUTH))
        .respond_with(not_found())
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(ADD_PATH))
        .and(header("authorization", AUTH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["ttl"], 60);
            assert_eq!(written_values(req), vec![format!("\"{VALUE}\"")]);
            ResponseTemplate::new(201).set_body_json(action_body(1, "add_rrset_records", "success"))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_appends_to_existing_rrset_without_ttl() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_body(&[OTHER_VALUE])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(ADD_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert!(
                body.get("ttl").is_none(),
                "an existing RRSet keeps its TTL: {body}"
            );
            // Only the new value is sent: add_records appends, so the other
            // value stays in place.
            assert_eq!(written_values(req), vec![format!("\"{VALUE}\"")]);
            ResponseTemplate::new(201).set_body_json(action_body(1, "add_rrset_records", "success"))
        })
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(REMOVE_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_skips_write_when_value_already_present() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_body(&[OTHER_VALUE, VALUE])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_waits_for_running_action() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(not_found())
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(ADD_PATH))
        .respond_with(ResponseTemplate::new(201).set_body_json(action_body(
            7,
            "add_rrset_records",
            "running",
        )))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/zones/actions/7"))
        .and(header("authorization", AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_json(action_body(
            7,
            "add_rrset_records",
            "success",
        )))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn failed_action_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(not_found())
        .mount(&server)
        .await;

    let mut failed = action_body(9, "add_rrset_records", "error");
    failed["action"]["error"] = json!({ "code": "action_failed", "message": "Action failed" });
    Mock::given(method("POST"))
        .and(path(ADD_PATH))
        .respond_with(ResponseTemplate::new(201).set_body_json(failed))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("hetzner"), "{msg}");
    assert!(msg.contains("action_failed"), "{msg}");
}

#[tokio::test]
async fn present_resolves_zone_via_api() {
    let server = MockServer::start().await;

    // The shortest candidate is tried first and is the zone.
    Mock::given(method("GET"))
        .and(path("/zones"))
        .and(query_param("name", "example.com"))
        .and(header("authorization", AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "zones": [{ "id": 42, "name": "example.com", "ttl": 3600 }],
            "meta": { "pagination": { "page": 1, "per_page": 25, "total_entries": 1 } }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/zones/example.com/rrsets/_acme-challenge.www/TXT"))
        .respond_with(not_found())
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(
            "/zones/example.com/rrsets/_acme-challenge.www/TXT/actions/add_records",
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(action_body(
            1,
            "add_rrset_records",
            "success",
        )))
        .expect(1)
        .mount(&server)
        .await;

    let config = HetznerConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap();
    let provider = HetznerProvider::new(config).unwrap();
    provider
        .present("_acme-challenge.www.example.com", VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn zone_lookup_walks_past_public_suffix() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones"))
        .and(query_param("name", "co.uk"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "zones": [] })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/zones"))
        .and(query_param("name", "example.co.uk"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "zones": [{ "id": 43, "name": "example.co.uk" }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/zones/example.co.uk/rrsets/_acme-challenge/TXT"))
        .respond_with(not_found())
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(
            "/zones/example.co.uk/rrsets/_acme-challenge/TXT/actions/add_records",
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(action_body(
            1,
            "add_rrset_records",
            "success",
        )))
        .expect(1)
        .mount(&server)
        .await;

    let config = HetznerConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap();
    let provider = HetznerProvider::new(config).unwrap();
    provider
        .present("_acme-challenge.example.co.uk", VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn present_fails_when_no_zone_matches() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "zones": [] })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let config = HetznerConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap();
    let provider = HetznerProvider::new(config).unwrap();
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, cheti::DnsError::ZoneNotFound(_)), "{err}");
}

#[tokio::test]
async fn cleanup_removes_last_value() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_body(&[VALUE])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(REMOVE_PATH))
        .and(header("authorization", AUTH))
        .respond_with(move |req: &Request| {
            assert_eq!(written_values(req), vec![format!("\"{VALUE}\"")]);
            ResponseTemplate::new(201).set_body_json(action_body(
                2,
                "remove_rrset_records",
                "success",
            ))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_removes_only_its_own_value() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_body(&[VALUE, OTHER_VALUE])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(REMOVE_PATH))
        .respond_with(move |req: &Request| {
            let values = written_values(req);
            assert_eq!(values, vec![format!("\"{VALUE}\"")]);
            assert!(!values.contains(&format!("\"{OTHER_VALUE}\"")));
            ResponseTemplate::new(201).set_body_json(action_body(
                2,
                "remove_rrset_records",
                "success",
            ))
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

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(not_found())
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
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

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_body(&[OTHER_VALUE])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn rate_limit_surfaces_reset_time() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(not_found())
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(ADD_PATH))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("ratelimit-reset", "1767225600")
                .set_body_json(json!({
                    "error": { "code": "rate_limit_exceeded", "message": "limit reached" }
                })),
        )
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("hetzner"), "{msg}");
    assert!(msg.contains("429"), "{msg}");
    assert!(msg.contains("1767225600"), "{msg}");
}

#[tokio::test]
async fn unauthorized_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": { "code": "unauthorized", "message": "unable to authenticate" }
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("hetzner"), "{msg}");
    assert!(msg.contains("401"), "{msg}");
    assert!(msg.contains("unauthorized"), "{msg}");
}

#[tokio::test]
async fn server_error_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("hetzner"), "{msg}");
    assert!(msg.contains("500"), "{msg}");
}

#[tokio::test]
async fn invalid_acme_value_is_rejected_before_http() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
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
    // Without the keyed lock, both calls would see no RRSet and each try to
    // create it with a TTL; the per-name lock makes the second call see the
    // RRSet created by the first and append to it.
    let server = MockServer::start().await;
    let state = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let in_flight = Arc::new(AtomicUsize::new(0));

    let state_get = state.clone();
    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(move |_: &Request| {
            let values = state_get.lock().unwrap().clone();
            if values.is_empty() {
                not_found()
            } else {
                let records: Vec<Value> = values.iter().map(|v| json!({ "value": v })).collect();
                ResponseTemplate::new(200).set_body_json(json!({
                    "rrset": {
                        "id": "_acme-challenge/TXT",
                        "name": "_acme-challenge",
                        "type": "TXT",
                        "ttl": 60,
                        "labels": {},
                        "protection": { "change": false },
                        "records": records,
                        "zone": 42,
                    }
                }))
            }
        })
        .mount(&server)
        .await;

    let state_add = state.clone();
    let in_flight_add = in_flight.clone();
    Mock::given(method("POST"))
        .and(path(ADD_PATH))
        .respond_with(move |req: &Request| {
            let concurrent = in_flight_add.fetch_add(1, Ordering::SeqCst);
            assert_eq!(concurrent, 0, "writes must not overlap");
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let mut values = state_add.lock().unwrap();
            if values.is_empty() {
                assert_eq!(body["ttl"], 60);
            } else {
                assert!(body.get("ttl").is_none(), "{body}");
            }
            std::thread::sleep(Duration::from_millis(50));
            values.extend(written_values(req));
            in_flight_add.fetch_sub(1, Ordering::SeqCst);
            ResponseTemplate::new(201).set_body_json(action_body(1, "add_rrset_records", "success"))
        })
        .expect(2)
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
    assert_eq!(final_state.len(), 2, "got {final_state:?}");
    assert!(final_state.contains(&format!("\"{VALUE}\"")));
    assert!(final_state.contains(&format!("\"{OTHER_VALUE}\"")));
}

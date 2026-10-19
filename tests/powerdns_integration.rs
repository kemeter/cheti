use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cheti::{DnsError, DnsProvider, PowerDnsConfig, PowerDnsProvider};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const FQDN: &str = "_acme-challenge.example.com";
const NAME: &str = "_acme-challenge.example.com.";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const ZONE_PATH: &str = "/api/v1/servers/localhost/zones/example.com.";
const API_KEY: &str = "test-key";

fn build_provider(server: &MockServer) -> PowerDnsProvider {
    let config = PowerDnsConfig::new(server.uri(), API_KEY)
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    PowerDnsProvider::new(config).unwrap()
}

fn zone_body(name: &str, rrsets: Vec<Value>) -> Value {
    json!({
        "id": name,
        "name": name,
        "kind": "Native",
        "serial": 2026010101,
        "rrsets": rrsets,
    })
}

fn txt_rrset(name: &str, ttl: u32, values: &[&str]) -> Value {
    let records: Vec<Value> = values
        .iter()
        .map(|v| json!({ "content": format!("\"{v}\""), "disabled": false }))
        .collect();
    json!({
        "name": name,
        "type": "TXT",
        "ttl": ttl,
        "records": records,
        "comments": [],
    })
}

fn rrset_lookup(rrsets: Vec<Value>) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(zone_body("example.com.", rrsets))
}

fn not_found() -> ResponseTemplate {
    ResponseTemplate::new(404).set_body_json(json!({ "error": "Not Found" }))
}

/// The single RRSet change sent in a PATCH body.
fn patched_rrset(req: &Request) -> Value {
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    let rrsets = body["rrsets"].as_array().unwrap();
    assert_eq!(rrsets.len(), 1, "{body}");
    rrsets[0].clone()
}

fn written_values(rrset: &Value) -> Vec<String> {
    rrset["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["content"].as_str().unwrap().to_string())
        .collect()
}

async fn mount_rrset_get(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(ZONE_PATH))
        .and(query_param("rrset_name", NAME))
        .and(query_param("rrset_type", "TXT"))
        .and(header("x-api-key", API_KEY))
        .respond_with(response)
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn present_creates_rrset_when_absent() {
    let server = MockServer::start().await;
    mount_rrset_get(&server, rrset_lookup(vec![])).await;

    Mock::given(method("PATCH"))
        .and(path(ZONE_PATH))
        .and(header("x-api-key", API_KEY))
        .respond_with(move |req: &Request| {
            let rrset = patched_rrset(req);
            assert_eq!(rrset["name"], NAME);
            assert_eq!(rrset["type"], "TXT");
            assert_eq!(rrset["changetype"], "REPLACE");
            assert_eq!(rrset["ttl"], 60);
            assert_eq!(written_values(&rrset), vec![format!("\"{VALUE}\"")]);
            assert_eq!(rrset["records"][0]["disabled"], false);
            ResponseTemplate::new(204)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_merges_with_existing_values_and_keeps_ttl() {
    let server = MockServer::start().await;
    mount_rrset_get(
        &server,
        rrset_lookup(vec![txt_rrset(NAME, 300, &[OTHER_VALUE])]),
    )
    .await;

    Mock::given(method("PATCH"))
        .and(path(ZONE_PATH))
        .respond_with(move |req: &Request| {
            let rrset = patched_rrset(req);
            assert_eq!(rrset["changetype"], "REPLACE");
            assert_eq!(rrset["ttl"], 300, "an existing RRSet keeps its TTL");
            let values = written_values(&rrset);
            assert_eq!(values.len(), 2, "{values:?}");
            assert!(values.contains(&format!("\"{OTHER_VALUE}\"")));
            assert!(values.contains(&format!("\"{VALUE}\"")));
            ResponseTemplate::new(204)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_ignores_unrelated_rrsets_from_unfiltered_server() {
    // A server that ignores the rrset filter returns the whole zone.
    let server = MockServer::start().await;
    mount_rrset_get(
        &server,
        rrset_lookup(vec![
            txt_rrset("example.com.", 3600, &["v=spf1 -all"]),
            txt_rrset("_acme-challenge.www.example.com.", 60, &[OTHER_VALUE]),
            json!({
                "name": NAME,
                "type": "CNAME",
                "ttl": 60,
                "records": [{ "content": "elsewhere.example.net.", "disabled": false }],
            }),
        ]),
    )
    .await;

    Mock::given(method("PATCH"))
        .and(path(ZONE_PATH))
        .respond_with(move |req: &Request| {
            let rrset = patched_rrset(req);
            assert_eq!(rrset["ttl"], 60);
            assert_eq!(written_values(&rrset), vec![format!("\"{VALUE}\"")]);
            ResponseTemplate::new(204)
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
    mount_rrset_get(
        &server,
        rrset_lookup(vec![txt_rrset(NAME, 60, &[OTHER_VALUE, VALUE])]),
    )
    .await;

    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_resolves_delegated_sub_zone() {
    let server = MockServer::start().await;

    // Longest suffix first: the fqdn itself is not a zone, its parent is a
    // delegated sub-zone, and the registrable domain is never queried.
    Mock::given(method("GET"))
        .and(path(
            "/api/v1/servers/localhost/zones/_acme-challenge.dev.example.com.",
        ))
        .and(query_param("rrsets", "false"))
        .and(header("x-api-key", API_KEY))
        .respond_with(not_found())
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/servers/localhost/zones/dev.example.com."))
        .and(query_param("rrsets", "false"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(zone_body("dev.example.com.", vec![])),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/servers/localhost/zones/dev.example.com."))
        .and(query_param(
            "rrset_name",
            "_acme-challenge.dev.example.com.",
        ))
        .and(query_param("rrset_type", "TXT"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(zone_body("dev.example.com.", vec![])),
        )
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(ZONE_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path("/api/v1/servers/localhost/zones/dev.example.com."))
        .respond_with(move |req: &Request| {
            let rrset = patched_rrset(req);
            assert_eq!(rrset["name"], "_acme-challenge.dev.example.com.");
            ResponseTemplate::new(204)
        })
        .expect(2)
        .mount(&server)
        .await;

    let config = PowerDnsConfig::new(server.uri(), API_KEY).unwrap();
    let provider = PowerDnsProvider::new(config).unwrap();
    // The second call reuses the cached zone: no further lookup.
    provider
        .present("_acme-challenge.dev.example.com", VALUE)
        .await
        .unwrap();
    provider
        .present("_acme-challenge.dev.example.com", OTHER_VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn custom_server_id_is_used_in_paths() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/servers/pdns-1/zones/example.com."))
        .and(query_param("rrset_name", NAME))
        .respond_with(rrset_lookup(vec![]))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path("/api/v1/servers/pdns-1/zones/example.com."))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let config = PowerDnsConfig::new(server.uri(), API_KEY)
        .unwrap()
        .with_server_id("pdns-1")
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    let provider = PowerDnsProvider::new(config).unwrap();
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_fails_when_no_zone_matches() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(not_found())
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let config = PowerDnsConfig::new(server.uri(), API_KEY).unwrap();
    let provider = PowerDnsProvider::new(config).unwrap();
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::ZoneNotFound(_)), "{err}");
}

#[tokio::test]
async fn cleanup_removes_only_its_own_value() {
    let server = MockServer::start().await;
    mount_rrset_get(
        &server,
        rrset_lookup(vec![txt_rrset(NAME, 120, &[VALUE, OTHER_VALUE])]),
    )
    .await;

    Mock::given(method("PATCH"))
        .and(path(ZONE_PATH))
        .and(header("x-api-key", API_KEY))
        .respond_with(move |req: &Request| {
            let rrset = patched_rrset(req);
            assert_eq!(rrset["changetype"], "REPLACE");
            assert_eq!(rrset["ttl"], 120);
            assert_eq!(written_values(&rrset), vec![format!("\"{OTHER_VALUE}\"")]);
            ResponseTemplate::new(204)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_deletes_rrset_when_last_value() {
    let server = MockServer::start().await;
    mount_rrset_get(&server, rrset_lookup(vec![txt_rrset(NAME, 60, &[VALUE])])).await;

    Mock::given(method("PATCH"))
        .and(path(ZONE_PATH))
        .respond_with(move |req: &Request| {
            let rrset = patched_rrset(req);
            assert_eq!(rrset["name"], NAME);
            assert_eq!(rrset["type"], "TXT");
            assert_eq!(rrset["changetype"], "DELETE");
            assert!(rrset.get("records").is_none(), "{rrset}");
            ResponseTemplate::new(204)
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
    mount_rrset_get(&server, rrset_lookup(vec![])).await;

    Mock::given(method("PATCH"))
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
    mount_rrset_get(
        &server,
        rrset_lookup(vec![txt_rrset(NAME, 60, &[OTHER_VALUE])]),
    )
    .await;

    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn unauthorized_surfaces_as_auth_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(ZONE_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Auth(_)), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("powerdns"), "{msg}");
    assert!(msg.contains("401"), "{msg}");
    assert!(!msg.contains(API_KEY), "the API key must not leak: {msg}");
}

#[tokio::test]
async fn forbidden_surfaces_as_auth_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(ZONE_PATH))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({ "error": "Forbidden" })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Auth(_)), "{err:?}");
}

#[tokio::test]
async fn unprocessable_surfaces_error_message() {
    let server = MockServer::start().await;
    mount_rrset_get(&server, rrset_lookup(vec![])).await;

    Mock::given(method("PATCH"))
        .and(path(ZONE_PATH))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "error": "RRset _acme-challenge.example.com. IN TXT: Conflicts with pre-existing RRset"
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Api(_)), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("powerdns"), "{msg}");
    assert!(msg.contains("422"), "{msg}");
    assert!(
        msg.contains("Conflicts with pre-existing RRset"),
        "the server message is surfaced: {msg}"
    );
    assert!(!msg.contains("{\"error\""), "raw JSON is unwrapped: {msg}");
}

#[tokio::test]
async fn server_error_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(ZONE_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, DnsError::Api(_)), "{err:?}");
    assert!(msg.contains("500"), "{msg}");
    assert!(msg.contains("boom"), "{msg}");
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
    // Without the keyed lock, both calls would read an empty RRSet and the
    // second REPLACE would drop the first value.
    let server = MockServer::start().await;
    let state = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let in_flight = Arc::new(AtomicUsize::new(0));

    let state_get = state.clone();
    Mock::given(method("GET"))
        .and(path(ZONE_PATH))
        .respond_with(move |_: &Request| {
            let values = state_get.lock().unwrap().clone();
            let rrsets = if values.is_empty() {
                vec![]
            } else {
                let records: Vec<Value> = values
                    .iter()
                    .map(|v| json!({ "content": v, "disabled": false }))
                    .collect();
                vec![json!({ "name": NAME, "type": "TXT", "ttl": 60, "records": records })]
            };
            rrset_lookup(rrsets)
        })
        .mount(&server)
        .await;

    let state_patch = state.clone();
    let in_flight_patch = in_flight.clone();
    Mock::given(method("PATCH"))
        .and(path(ZONE_PATH))
        .respond_with(move |req: &Request| {
            let concurrent = in_flight_patch.fetch_add(1, Ordering::SeqCst);
            assert_eq!(concurrent, 0, "writes must not overlap");
            std::thread::sleep(Duration::from_millis(50));
            *state_patch.lock().unwrap() = written_values(&patched_rrset(req));
            in_flight_patch.fetch_sub(1, Ordering::SeqCst);
            ResponseTemplate::new(204)
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

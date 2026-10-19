use std::sync::{Arc, Mutex};

use cheti::{BunnyConfig, BunnyProvider, DnsError, DnsProvider};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const ZONE_ID: i64 = 4242;
const FQDN: &str = "_acme-challenge.example.com";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const ZONE_PATH: &str = "/dnszone/4242";
const RECORDS_PATH: &str = "/dnszone/4242/records";

fn build_provider(server: &MockServer) -> BunnyProvider {
    let config = BunnyConfig::new("test-key")
        .with_api_base(server.uri())
        .unwrap();
    BunnyProvider::new(config).unwrap()
}

fn txt_record(id: i64, name: &str, value: &str) -> Value {
    json!({
        "Id": id,
        "Type": 3,
        "Ttl": 60,
        "Value": value,
        "Name": name,
        "Weight": 0,
        "Priority": 0,
        "Port": 0,
        "Disabled": false
    })
}

fn zone_summary(id: i64, domain: &str) -> Value {
    json!({ "Id": id, "Domain": domain, "Records": [] })
}

fn zone_list(zones: Vec<Value>, has_more: bool) -> Value {
    let total = zones.len();
    json!({
        "Items": zones,
        "CurrentPage": 1,
        "TotalItems": total,
        "HasMoreItems": has_more
    })
}

async fn mount_zone_list(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/dnszone"))
        .and(query_param("search", ZONE))
        .and(header("AccessKey", "test-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(zone_list(vec![zone_summary(ZONE_ID, ZONE)], false)),
        )
        .mount(server)
        .await;
}

async fn mount_zone(server: &MockServer, records: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path(ZONE_PATH))
        .and(header("AccessKey", "test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Id": ZONE_ID,
            "Domain": ZONE,
            "Records": records
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn present_creates_record_when_absent() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    mount_zone(&server, vec![]).await;

    Mock::given(method("PUT"))
        .and(path(RECORDS_PATH))
        .and(header("AccessKey", "test-key"))
        .and(body_json(json!({
            "Type": 3,
            "Ttl": 60,
            "Value": VALUE,
            "Name": "_acme-challenge"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(txt_record(
            1,
            "_acme-challenge",
            VALUE,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_is_idempotent_when_value_already_present() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    mount_zone(&server, vec![txt_record(1, "_acme-challenge", VALUE)]).await;

    Mock::given(method("PUT"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_ignores_same_value_on_other_name_or_type() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    let mut cname = txt_record(1, "_acme-challenge", VALUE);
    cname["Type"] = json!(2);
    mount_zone(
        &server,
        vec![cname, txt_record(2, "_acme-challenge.other", VALUE)],
    )
    .await;

    Mock::given(method("PUT"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(201).set_body_json(txt_record(
            3,
            "_acme-challenge",
            VALUE,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_creates_alongside_existing_other_value() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    mount_zone(&server, vec![txt_record(1, "_acme-challenge", OTHER_VALUE)]).await;

    Mock::given(method("PUT"))
        .and(path(RECORDS_PATH))
        .and(body_json(json!({
            "Type": 3,
            "Ttl": 60,
            "Value": VALUE,
            "Name": "_acme-challenge"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(txt_record(
            2,
            "_acme-challenge",
            VALUE,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_uses_empty_name_for_apex() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    mount_zone(&server, vec![]).await;

    Mock::given(method("PUT"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["Name"], "");
            ResponseTemplate::new(201).set_body_json(txt_record(3, "", VALUE))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(ZONE, VALUE).await.unwrap();
}

#[tokio::test]
async fn mixed_case_fqdn_is_matched() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    mount_zone(&server, vec![txt_record(1, "_ACME-Challenge", VALUE)]).await;

    Mock::given(method("PUT"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider
        .present("_acme-challenge.Example.COM", VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn zone_lookup_picks_longest_suffix_across_pages() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/dnszone"))
        .and(query_param("search", ZONE))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(zone_list(
            vec![
                zone_summary(1, "example.com"),
                zone_summary(2, "badsub.example.com"),
            ],
            true,
        )))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/dnszone"))
        .and(query_param("search", ZONE))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(zone_list(
            vec![
                zone_summary(3, "sub.example.com"),
                zone_summary(4, "notexample.com"),
            ],
            false,
        )))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/dnszone/3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Id": 3,
            "Domain": "sub.example.com",
            "Records": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/dnszone/3/records"))
        .and(body_json(json!({
            "Type": 3,
            "Ttl": 60,
            "Value": VALUE,
            "Name": "_acme-challenge"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(txt_record(
            9,
            "_acme-challenge",
            VALUE,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider
        .present("_acme-challenge.sub.example.com", VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn with_zone_selects_exact_domain() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/dnszone"))
        .and(query_param("search", ZONE))
        .respond_with(ResponseTemplate::new(200).set_body_json(zone_list(
            vec![
                zone_summary(7, "sub.example.com"),
                zone_summary(ZONE_ID, ZONE),
            ],
            false,
        )))
        .mount(&server)
        .await;
    mount_zone(&server, vec![]).await;

    Mock::given(method("PUT"))
        .and(path(RECORDS_PATH))
        .and(body_json(json!({
            "Type": 3,
            "Ttl": 60,
            "Value": VALUE,
            "Name": "_acme-challenge.sub"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(txt_record(
            5,
            "_acme-challenge.sub",
            VALUE,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let config = BunnyConfig::new("test-key")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone("Example.com")
        .unwrap();
    let provider = BunnyProvider::new(config).unwrap();
    provider
        .present("_acme-challenge.sub.example.com", VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn unknown_zone_surfaces_as_zone_not_found() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/dnszone"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(zone_list(vec![zone_summary(1, "other.com")], false)),
        )
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::ZoneNotFound(_)), "{err}");
}

#[tokio::test]
async fn cleanup_deletes_matching_record_only() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    mount_zone(
        &server,
        vec![
            txt_record(11, "_acme-challenge", OTHER_VALUE),
            txt_record(22, "_acme-challenge", VALUE),
            txt_record(33, "_acme-challenge.other", VALUE),
        ],
    )
    .await;

    Mock::given(method("DELETE"))
        .and(path(format!("{RECORDS_PATH}/22")))
        .and(header("AccessKey", "test-key"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("{RECORDS_PATH}/11")))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("{RECORDS_PATH}/33")))
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
    mount_zone_list(&server).await;
    mount_zone(
        &server,
        vec![txt_record(11, "_acme-challenge", OTHER_VALUE)],
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
    mount_zone_list(&server).await;
    mount_zone(&server, vec![txt_record(33, "_acme-challenge", VALUE)]).await;

    Mock::given(method("DELETE"))
        .and(path(format!("{RECORDS_PATH}/33")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

/// Wildcard + apex issuance places two values on the same name; each cleanup
/// must leave the other value in place.
#[tokio::test]
async fn two_values_on_same_name_coexist() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    let records: Arc<Mutex<Vec<(i64, String)>>> = Arc::new(Mutex::new(Vec::new()));

    let list_state = Arc::clone(&records);
    Mock::given(method("GET"))
        .and(path(ZONE_PATH))
        .respond_with(move |_: &Request| {
            let items: Vec<Value> = list_state
                .lock()
                .unwrap()
                .iter()
                .map(|(id, value)| txt_record(*id, "_acme-challenge", value))
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({
                "Id": ZONE_ID,
                "Domain": ZONE,
                "Records": items
            }))
        })
        .mount(&server)
        .await;

    let create_state = Arc::clone(&records);
    Mock::given(method("PUT"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let value = body["Value"].as_str().unwrap().to_string();
            let mut state = create_state.lock().unwrap();
            let id = state.len() as i64 + 100;
            state.push((id, value.clone()));
            ResponseTemplate::new(201).set_body_json(txt_record(id, "_acme-challenge", &value))
        })
        .expect(2)
        .mount(&server)
        .await;

    let delete_state = Arc::clone(&records);
    Mock::given(method("DELETE"))
        .respond_with(move |req: &Request| {
            let id: i64 = req.url.path().rsplit('/').next().unwrap().parse().unwrap();
            delete_state.lock().unwrap().retain(|(rid, _)| *rid != id);
            ResponseTemplate::new(204)
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
    provider.present(FQDN, OTHER_VALUE).await.unwrap();
    provider.cleanup(FQDN, VALUE).await.unwrap();

    let remaining: Vec<String> = records
        .lock()
        .unwrap()
        .iter()
        .map(|(_, value)| value.clone())
        .collect();
    assert_eq!(remaining, vec![OTHER_VALUE.to_string()]);
}

#[tokio::test]
async fn http_401_surfaces_as_auth_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/dnszone"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Auth(_)), "{err:?}");
    assert!(!err.to_string().contains("test-key"), "{err}");
}

#[tokio::test]
async fn http_429_surfaces_as_rate_limit() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    mount_zone(&server, vec![]).await;

    Mock::given(method("PUT"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rate limited"), "{msg}");
    assert!(msg.contains("retry after 7s"), "{msg}");
}

#[tokio::test]
async fn create_failure_surfaces_bunny_error_body() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    mount_zone(&server, vec![]).await;

    Mock::given(method("PUT"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "ErrorKey": "dnszone.record.invalid",
            "Field": "Ttl",
            "Message": "The TTL value is invalid."
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("PUT"), "{msg}");
    assert!(msg.contains("400"), "{msg}");
    assert!(msg.contains("dnszone.record.invalid"), "{msg}");
    assert!(msg.contains("The TTL value is invalid."), "{msg}");
}

#[tokio::test]
async fn delete_failure_surfaces_as_api_error() {
    let server = MockServer::start().await;
    mount_zone_list(&server).await;
    mount_zone(&server, vec![txt_record(44, "_acme-challenge", VALUE)]).await;

    Mock::given(method("DELETE"))
        .and(path(format!("{RECORDS_PATH}/44")))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.cleanup(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("DELETE"), "{msg}");
    assert!(msg.contains("500"), "{msg}");
    assert!(msg.contains("boom"), "{msg}");
}

#[tokio::test]
async fn fqdn_outside_override_zone_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dnszone"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(zone_list(vec![zone_summary(ZONE_ID, ZONE)], false)),
        )
        .mount(&server)
        .await;

    let config = BunnyConfig::new("test-key")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    let provider = BunnyProvider::new(config).unwrap();
    let err = provider
        .present("_acme-challenge.other.org", VALUE)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not within zone"), "{err}");
}

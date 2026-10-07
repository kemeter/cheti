use std::sync::{Arc, Mutex};

use cheti::{DigitalOceanConfig, DigitalOceanProvider, DnsError, DnsProvider};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE: &str = "example.com";
const FQDN: &str = "_acme-challenge.example.com";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const RECORDS_PATH: &str = "/domains/example.com/records";

fn build_provider(server: &MockServer) -> DigitalOceanProvider {
    let config = DigitalOceanConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone(ZONE)
        .unwrap();
    DigitalOceanProvider::new(config).unwrap()
}

fn txt_record(id: u64, name: &str, data: &str) -> Value {
    json!({
        "id": id,
        "type": "TXT",
        "name": name,
        "data": data,
        "priority": null,
        "port": null,
        "ttl": 30,
        "weight": null,
        "flags": null,
        "tag": null
    })
}

fn record_list(records: Vec<Value>) -> Value {
    let total = records.len();
    json!({
        "domain_records": records,
        "links": {},
        "meta": { "total": total }
    })
}

async fn mount_list(server: &MockServer, records: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .and(query_param("type", "TXT"))
        .and(query_param("name", FQDN))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(record_list(records)))
        .mount(server)
        .await;
}

#[tokio::test]
async fn present_creates_record_when_absent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .and(query_param("type", "TXT"))
        .and(query_param("name", FQDN))
        .and(query_param("page", "1"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(record_list(vec![])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .and(header("authorization", "Bearer test-token"))
        .and(body_json(json!({
            "type": "TXT",
            "name": "_acme-challenge",
            "data": VALUE,
            "ttl": 30
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "domain_record": txt_record(1, "_acme-challenge", VALUE)
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_is_idempotent_when_value_already_present() {
    let server = MockServer::start().await;
    mount_list(&server, vec![txt_record(1, "_acme-challenge", VALUE)]).await;

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
async fn mixed_case_zone_and_fqdn_are_matched() {
    let server = MockServer::start().await;
    mount_list(&server, vec![]).await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .and(body_json(json!({
            "type": "TXT",
            "name": "_acme-challenge",
            "data": VALUE,
            "ttl": 30
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "domain_record": txt_record(1, "_acme-challenge", VALUE)
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = DigitalOceanConfig::new("test-token")
        .with_api_base(server.uri())
        .unwrap()
        .with_zone("Example.COM")
        .unwrap();
    let provider = DigitalOceanProvider::new(config).unwrap();
    provider
        .present("_acme-challenge.Example.com", VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn present_creates_alongside_existing_other_value() {
    let server = MockServer::start().await;
    mount_list(&server, vec![txt_record(1, "_acme-challenge", OTHER_VALUE)]).await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .and(body_json(json!({
            "type": "TXT",
            "name": "_acme-challenge",
            "data": VALUE,
            "ttl": 30
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "domain_record": txt_record(2, "_acme-challenge", VALUE)
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_uses_at_for_apex() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .and(query_param("name", ZONE))
        .respond_with(ResponseTemplate::new(200).set_body_json(record_list(vec![])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["name"], "@");
            ResponseTemplate::new(201).set_body_json(json!({
                "domain_record": txt_record(3, "@", VALUE)
            }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(ZONE, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_follows_pagination() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "domain_records": [txt_record(1, "_acme-challenge", OTHER_VALUE)],
            "links": { "pages": {
                "last": "https://api.digitalocean.com/v2/domains/example.com/records?page=2",
                "next": "https://api.digitalocean.com/v2/domains/example.com/records?page=2"
            } },
            "meta": { "total": 2 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "domain_records": [txt_record(2, "_acme-challenge", VALUE)],
            "links": { "pages": {
                "first": "https://api.digitalocean.com/v2/domains/example.com/records?page=1",
                "prev": "https://api.digitalocean.com/v2/domains/example.com/records?page=1"
            } },
            "meta": { "total": 2 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // The value sits on page 2: no record must be created.
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
async fn cleanup_deletes_matching_record_only() {
    let server = MockServer::start().await;
    mount_list(
        &server,
        vec![
            txt_record(11, "_acme-challenge", OTHER_VALUE),
            txt_record(22, "_acme-challenge", VALUE),
        ],
    )
    .await;

    Mock::given(method("DELETE"))
        .and(path(format!("{RECORDS_PATH}/22")))
        .and(header("authorization", "Bearer test-token"))
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

    let provider = build_provider(&server);
    provider.cleanup(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn cleanup_is_noop_when_value_absent() {
    let server = MockServer::start().await;
    mount_list(
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
    mount_list(&server, vec![txt_record(33, "_acme-challenge", VALUE)]).await;

    Mock::given(method("DELETE"))
        .and(path(format!("{RECORDS_PATH}/33")))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "id": "not_found",
            "message": "The resource you requested could not be found."
        })))
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
    let records: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));

    let list_state = Arc::clone(&records);
    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(move |_: &Request| {
            let items: Vec<Value> = list_state
                .lock()
                .unwrap()
                .iter()
                .map(|(id, data)| txt_record(*id, "_acme-challenge", data))
                .collect();
            ResponseTemplate::new(200).set_body_json(record_list(items))
        })
        .mount(&server)
        .await;

    let create_state = Arc::clone(&records);
    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let data = body["data"].as_str().unwrap().to_string();
            let mut state = create_state.lock().unwrap();
            let id = state.len() as u64 + 100;
            state.push((id, data.clone()));
            ResponseTemplate::new(201).set_body_json(json!({
                "domain_record": txt_record(id, "_acme-challenge", &data)
            }))
        })
        .expect(2)
        .mount(&server)
        .await;

    let delete_state = Arc::clone(&records);
    Mock::given(method("DELETE"))
        .respond_with(move |req: &Request| {
            let id: u64 = req.url.path().rsplit('/').next().unwrap().parse().unwrap();
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
        .map(|(_, data)| data.clone())
        .collect();
    assert_eq!(remaining, vec![OTHER_VALUE.to_string()]);
}

#[tokio::test]
async fn unknown_domain_surfaces_as_zone_not_found() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "id": "not_found",
            "message": "The resource you requested could not be found."
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::ZoneNotFound(_)), "{err}");
}

#[tokio::test]
async fn http_401_surfaces_as_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "id": "unauthorized",
            "message": "Unable to authenticate you."
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("digitalocean"), "{msg}");
    assert!(msg.contains("401"), "{msg}");
    assert!(msg.contains("Unable to authenticate you."), "{msg}");
}

#[tokio::test]
async fn create_failure_surfaces_as_api_error() {
    let server = MockServer::start().await;
    mount_list(&server, vec![]).await;

    Mock::given(method("POST"))
        .and(path(RECORDS_PATH))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "id": "unprocessable_entity",
            "message": "Ttl must be greater than or equal to 30."
        })))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("POST"), "{msg}");
    assert!(msg.contains("422"), "{msg}");
}

#[tokio::test]
async fn delete_failure_surfaces_as_api_error() {
    let server = MockServer::start().await;
    mount_list(&server, vec![txt_record(44, "_acme-challenge", VALUE)]).await;

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
}

#[tokio::test]
async fn fqdn_outside_zone_is_rejected() {
    let server = MockServer::start().await;
    let provider = build_provider(&server);
    let err = provider
        .present("_acme-challenge.other.org", VALUE)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not within zone"), "{err}");
}

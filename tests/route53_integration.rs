use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cheti::{DnsError, DnsProvider, Route53Config, Route53Provider};
use wiremock::matchers::{header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ZONE_ID: &str = "Z0EXAMPLE";
const FQDN: &str = "_acme-challenge.example.com";
const NAME: &str = "_acme-challenge.example.com.";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const RRSET_PATH: &str = "/2013-04-01/hostedzone/Z0EXAMPLE/rrset";
const CHANGE_PATH: &str = "/2013-04-01/hostedzone/Z0EXAMPLE/rrset/";
const ACCESS_KEY_ID: &str = "AKIDTEST";

fn config(server: &MockServer) -> Route53Config {
    Route53Config::new(ACCESS_KEY_ID, "test-secret")
        .with_api_base(format!("{}/2013-04-01", server.uri()))
        .unwrap()
}

fn build_provider(server: &MockServer) -> Route53Provider {
    Route53Provider::new(config(server).with_hosted_zone_id(ZONE_ID).unwrap()).unwrap()
}

fn xml(body: String) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body, "text/xml")
}

fn rrset_list(name: &str, ttl: u32, values: &[&str]) -> ResponseTemplate {
    let records: String = values
        .iter()
        .map(|v| format!("<ResourceRecord><Value>&quot;{v}&quot;</Value></ResourceRecord>"))
        .collect();
    xml(format!(
        r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>{name}</Name>
      <Type>TXT</Type>
      <TTL>{ttl}</TTL>
      <ResourceRecords>{records}</ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>true</IsTruncated>
  <MaxItems>1</MaxItems>
</ListResourceRecordSetsResponse>"#
    ))
}

fn empty_rrset_list() -> ResponseTemplate {
    xml(r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets/>
  <IsTruncated>false</IsTruncated>
  <MaxItems>1</MaxItems>
</ListResourceRecordSetsResponse>"#
        .to_string())
}

fn change_info(id: &str, status: &str) -> ResponseTemplate {
    xml(format!(
        r#"<?xml version="1.0"?>
<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeInfo>
    <Id>/change/{id}</Id>
    <Status>{status}</Status>
    <SubmittedAt>2026-01-01T00:00:00.000Z</SubmittedAt>
  </ChangeInfo>
</ChangeResourceRecordSetsResponse>"#
    ))
}

fn hosted_zones(zones: &[(&str, &str, bool)]) -> ResponseTemplate {
    let items: String = zones
        .iter()
        .map(|(id, name, private)| {
            format!(
                "<HostedZone><Id>/hostedzone/{id}</Id><Name>{name}</Name>\
                 <CallerReference>ref</CallerReference>\
                 <Config><PrivateZone>{private}</PrivateZone></Config>\
                 <ResourceRecordSetCount>2</ResourceRecordSetCount></HostedZone>"
            )
        })
        .collect();
    xml(format!(
        r#"<?xml version="1.0"?>
<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <HostedZones>{items}</HostedZones>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListHostedZonesByNameResponse>"#
    ))
}

fn error_response(status: u16, code: &str, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(
        format!(
            r#"<?xml version="1.0"?>
<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <Error><Type>Sender</Type><Code>{code}</Code><Message>{message}</Message></Error>
  <RequestId>00000000-0000-0000-0000-000000000000</RequestId>
</ErrorResponse>"#
        ),
        "text/xml",
    )
}

fn body(req: &Request) -> String {
    String::from_utf8(req.body.clone()).unwrap()
}

fn written_values(req: &Request) -> Vec<String> {
    body(req)
        .split("<Value>")
        .skip(1)
        .map(|s| s.split("</Value>").next().unwrap().to_string())
        .collect()
}

fn quoted(value: &str) -> String {
    format!("&quot;{value}&quot;")
}

fn mount_rrset(response: ResponseTemplate) -> Mock {
    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .and(query_param("name", NAME))
        .and(query_param("type", "TXT"))
        .and(query_param("maxitems", "1"))
        .respond_with(response)
}

#[tokio::test]
async fn present_creates_rrset_when_absent() {
    let server = MockServer::start().await;

    mount_rrset(empty_rrset_list())
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(CHANGE_PATH))
        .and(header_exists("x-amz-date"))
        .respond_with(move |req: &Request| {
            let auth = req.headers.get("authorization").unwrap().to_str().unwrap();
            assert!(
                auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDTEST/"),
                "{auth}"
            );
            assert!(auth.contains("/us-east-1/route53/aws4_request"), "{auth}");
            assert!(auth.contains("SignedHeaders=host;x-amz-date,"), "{auth}");
            let xml = body(req);
            assert!(xml.contains("<Action>UPSERT</Action>"), "{xml}");
            assert!(xml.contains(&format!("<Name>{NAME}</Name>")), "{xml}");
            assert!(xml.contains("<TTL>60</TTL>"), "{xml}");
            assert_eq!(written_values(req), vec![quoted(VALUE)]);
            change_info("C1", "INSYNC")
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

    mount_rrset(rrset_list(NAME, 300, &[OTHER_VALUE]))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(CHANGE_PATH))
        .respond_with(move |req: &Request| {
            let xml = body(req);
            assert!(xml.contains("<Action>UPSERT</Action>"), "{xml}");
            assert!(xml.contains("<TTL>300</TTL>"), "{xml}");
            // UPSERT replaces the whole set, so the other value is written back.
            assert_eq!(
                written_values(req),
                vec![quoted(OTHER_VALUE), quoted(VALUE)]
            );
            change_info("C1", "INSYNC")
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

    mount_rrset(rrset_list(NAME, 60, &[OTHER_VALUE, VALUE]))
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
async fn present_ignores_following_rrset_of_another_name() {
    // The listing starts at name/type and returns the next set when ours
    // does not exist.
    let server = MockServer::start().await;

    mount_rrset(rrset_list(
        "_acme-challenge.www.example.com.",
        300,
        &[OTHER_VALUE],
    ))
    .expect(1)
    .mount(&server)
    .await;

    Mock::given(method("POST"))
        .and(path(CHANGE_PATH))
        .respond_with(move |req: &Request| {
            assert!(body(req).contains("<TTL>60</TTL>"));
            assert_eq!(written_values(req), vec![quoted(VALUE)]);
            change_info("C1", "INSYNC")
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn present_waits_for_change_to_be_insync() {
    let server = MockServer::start().await;

    mount_rrset(empty_rrset_list()).mount(&server).await;

    Mock::given(method("POST"))
        .and(path(CHANGE_PATH))
        .respond_with(change_info("C2PENDING", "PENDING"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/2013-04-01/change/C2PENDING"))
        .and(header_exists("authorization"))
        .respond_with(xml(r#"<?xml version="1.0"?>
<GetChangeResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeInfo>
    <Id>/change/C2PENDING</Id>
    <Status>INSYNC</Status>
    <SubmittedAt>2026-01-01T00:00:00.000Z</SubmittedAt>
  </ChangeInfo>
</GetChangeResponse>"#
            .to_string()))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn session_token_is_sent_and_signed() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .and(header("x-amz-security-token", "session-token"))
        .respond_with(move |req: &Request| {
            let auth = req.headers.get("authorization").unwrap().to_str().unwrap();
            assert!(
                auth.contains("SignedHeaders=host;x-amz-date;x-amz-security-token,"),
                "{auth}"
            );
            rrset_list(NAME, 60, &[VALUE])
        })
        .expect(1)
        .mount(&server)
        .await;

    let config = config(&server)
        .with_session_token("session-token")
        .with_hosted_zone_id(ZONE_ID)
        .unwrap();
    let provider = Route53Provider::new(config).unwrap();
    provider.present(FQDN, VALUE).await.unwrap();
}

#[tokio::test]
async fn zone_lookup_picks_longest_public_zone() {
    let server = MockServer::start().await;

    // No zone is named after the fqdn itself.
    Mock::given(method("GET"))
        .and(path("/2013-04-01/hostedzonesbyname"))
        .and(query_param("dnsname", "_acme-challenge.www.example.com"))
        .respond_with(hosted_zones(&[("ZWWWPRIV", "www.example.com.", true)]))
        .expect(1)
        .mount(&server)
        .await;

    // Only a private zone has this name: it is skipped.
    Mock::given(method("GET"))
        .and(path("/2013-04-01/hostedzonesbyname"))
        .and(query_param("dnsname", "www.example.com"))
        .and(query_param("maxitems", "100"))
        .respond_with(hosted_zones(&[
            ("ZWWWPRIV", "www.example.com.", true),
            ("ZOTHER", "zzz.example.com.", false),
        ]))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/2013-04-01/hostedzonesbyname"))
        .and(query_param("dnsname", "example.com"))
        .respond_with(hosted_zones(&[
            ("ZPRIV", "example.com.", true),
            ("ZPUB", "example.com.", false),
        ]))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/2013-04-01/hostedzone/ZPUB/rrset"))
        .and(query_param("name", "_acme-challenge.www.example.com."))
        .respond_with(empty_rrset_list())
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/2013-04-01/hostedzone/ZPUB/rrset/"))
        .respond_with(change_info("C1", "INSYNC"))
        .expect(1)
        .mount(&server)
        .await;

    let provider = Route53Provider::new(config(&server)).unwrap();
    provider
        .present("_acme-challenge.www.example.com", VALUE)
        .await
        .unwrap();
    // The zone found by present is reused: no new lookup is mounted for it.
    provider
        .cleanup("_acme-challenge.www.example.com", VALUE)
        .await
        .unwrap();
}

#[tokio::test]
async fn zone_lookup_rejects_ambiguous_public_zones() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2013-04-01/hostedzonesbyname"))
        .and(query_param("dnsname", FQDN))
        .respond_with(hosted_zones(&[]))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/2013-04-01/hostedzonesbyname"))
        .and(query_param("dnsname", "example.com"))
        .respond_with(hosted_zones(&[
            ("ZONE1", "example.com.", false),
            ("ZONE2", "example.com.", false),
        ]))
        .mount(&server)
        .await;

    let provider = Route53Provider::new(config(&server)).unwrap();
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(err.to_string().contains("with_hosted_zone_id"), "{err}");
}

#[tokio::test]
async fn present_fails_when_no_zone_matches() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2013-04-01/hostedzonesbyname"))
        .respond_with(hosted_zones(&[("ZOTHER", "other.org.", false)]))
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let provider = Route53Provider::new(config(&server)).unwrap();
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::ZoneNotFound(_)), "{err}");
}

#[tokio::test]
async fn cleanup_deletes_rrset_holding_only_its_value() {
    let server = MockServer::start().await;

    mount_rrset(rrset_list(NAME, 120, &[VALUE]))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(CHANGE_PATH))
        .respond_with(move |req: &Request| {
            let xml = body(req);
            assert!(xml.contains("<Action>DELETE</Action>"), "{xml}");
            // DELETE must match the current set, TTL included.
            assert!(xml.contains("<TTL>120</TTL>"), "{xml}");
            assert_eq!(written_values(req), vec![quoted(VALUE)]);
            change_info("C1", "INSYNC")
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

    mount_rrset(rrset_list(NAME, 120, &[VALUE, OTHER_VALUE]))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(CHANGE_PATH))
        .respond_with(move |req: &Request| {
            let xml = body(req);
            assert!(xml.contains("<Action>UPSERT</Action>"), "{xml}");
            assert!(xml.contains("<TTL>120</TTL>"), "{xml}");
            assert_eq!(written_values(req), vec![quoted(OTHER_VALUE)]);
            change_info("C1", "INSYNC")
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

    mount_rrset(empty_rrset_list())
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

    mount_rrset(rrset_list(NAME, 60, &[OTHER_VALUE]))
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
async fn refused_credentials_surface_as_auth_error() {
    for code in [
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "AccessDenied",
    ] {
        let server = MockServer::start().await;

        mount_rrset(error_response(403, code, "refused"))
            .mount(&server)
            .await;

        let provider = build_provider(&server);
        let err = provider.present(FQDN, VALUE).await.unwrap_err();
        assert!(matches!(err, DnsError::Auth(_)), "{code}: {err:?}");
        let msg = err.to_string();
        assert!(msg.contains(code), "{msg}");
        assert!(!msg.contains("test-secret"), "{msg}");
    }
}

#[tokio::test]
async fn throttling_surfaces_as_rate_limit() {
    let server = MockServer::start().await;

    mount_rrset(empty_rrset_list()).mount(&server).await;

    Mock::given(method("POST"))
        .and(path(CHANGE_PATH))
        .respond_with(error_response(400, "Throttling", "Rate exceeded"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Api(_)), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("route53"), "{msg}");
    assert!(msg.contains("rate limited"), "{msg}");
    assert!(msg.contains("Throttling"), "{msg}");
}

#[tokio::test]
async fn unknown_hosted_zone_surfaces_as_zone_not_found() {
    let server = MockServer::start().await;

    mount_rrset(error_response(
        404,
        "NoSuchHostedZone",
        "No hosted zone found with ID: Z0EXAMPLE",
    ))
    .mount(&server)
    .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::ZoneNotFound(_)), "{err:?}");
}

#[tokio::test]
async fn rejected_change_batch_surfaces_as_api_error() {
    let server = MockServer::start().await;

    mount_rrset(rrset_list(NAME, 60, &[VALUE]))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(CHANGE_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_raw(
            r#"<?xml version="1.0"?>
<InvalidChangeBatch xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <Messages><Message>Tried to delete resource record set but it was not found</Message></Messages>
  <RequestId>00000000-0000-0000-0000-000000000000</RequestId>
</InvalidChangeBatch>"#,
            "text/xml",
        ))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.cleanup(FQDN, VALUE).await.unwrap_err();
    assert!(matches!(err, DnsError::Api(_)), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("InvalidChangeBatch"), "{msg}");
    assert!(msg.contains("not found"), "{msg}");
}

#[tokio::test]
async fn server_error_surfaces_as_api_error() {
    let server = MockServer::start().await;

    mount_rrset(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let provider = build_provider(&server);
    let err = provider.present(FQDN, VALUE).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("route53"), "{msg}");
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
    // Without the keyed lock, both calls would read an empty set and the
    // second UPSERT would drop the first value; the per-name lock makes the
    // second call see the first value and write both.
    let server = MockServer::start().await;
    let state = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let in_flight = Arc::new(AtomicUsize::new(0));

    let state_get = state.clone();
    Mock::given(method("GET"))
        .and(path(RRSET_PATH))
        .respond_with(move |_: &Request| {
            let values = state_get.lock().unwrap().clone();
            if values.is_empty() {
                empty_rrset_list()
            } else {
                let unquoted: Vec<String> = values
                    .iter()
                    .map(|v| {
                        v.trim_start_matches("&quot;")
                            .trim_end_matches("&quot;")
                            .to_string()
                    })
                    .collect();
                let refs: Vec<&str> = unquoted.iter().map(String::as_str).collect();
                rrset_list(NAME, 60, &refs)
            }
        })
        .mount(&server)
        .await;

    let state_post = state.clone();
    let in_flight_post = in_flight.clone();
    Mock::given(method("POST"))
        .and(path(CHANGE_PATH))
        .respond_with(move |req: &Request| {
            let concurrent = in_flight_post.fetch_add(1, Ordering::SeqCst);
            assert_eq!(concurrent, 0, "writes must not overlap");
            std::thread::sleep(Duration::from_millis(50));
            *state_post.lock().unwrap() = written_values(req);
            in_flight_post.fetch_sub(1, Ordering::SeqCst);
            change_info("C1", "INSYNC")
        })
        .expect(2)
        .mount(&server)
        .await;

    let provider = Arc::new(build_provider(&server));

    let p1 = provider.clone();
    let p2 = provider.clone();
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move { p1.present(FQDN, VALUE).await }),
        tokio::spawn(async move { p2.present(FQDN, OTHER_VALUE).await }),
    );
    r1.unwrap().unwrap();
    r2.unwrap().unwrap();

    let final_state = state.lock().unwrap().clone();
    assert_eq!(final_state.len(), 2, "got {final_state:?}");
    assert!(final_state.contains(&quoted(VALUE)));
    assert!(final_state.contains(&quoted(OTHER_VALUE)));
}

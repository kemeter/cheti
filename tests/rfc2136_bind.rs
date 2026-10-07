//! `Rfc2136Provider` against a real BIND primary.
//!
//! Marked `#[ignore]` because it needs the BIND container running. To execute:
//!
//!     ./scripts/bind-up.sh
//!     cargo test --test rfc2136_bind -- --ignored
//!     ./scripts/bind-down.sh
//!
//! Keys and zone are in tests/data/bind. The tests share one zone, so each
//! one writes under its own owner name.

use cheti::{DnsError, DnsProvider, Rfc2136Config, Rfc2136Provider, TsigAlgorithm};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const NAMESERVER: &str = "127.0.0.1:5300";
const ZONE: &str = "example.com";
const SHA256_KEY: &str = "cheti-sha256";
const SHA256_SECRET: &str = "Y2hldGktdGVzdC1zZWNyZXQtZm9yLXRzaWctaG1hYyEh";
const SHA512_KEY: &str = "cheti-sha512";
const SHA512_SECRET: &str = "Y2hldGktYmluZC1zaGE1MTItdGVzdC1zZWNyZXQtMDEyMzQ1Njc4OQ==";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";

fn provider(key: &str, secret: &str, algorithm: TsigAlgorithm) -> Rfc2136Provider {
    let config = Rfc2136Config::new(NAMESERVER, key, secret)
        .with_algorithm(algorithm)
        .with_zone(ZONE)
        .unwrap();
    Rfc2136Provider::new(config).unwrap()
}

/// Reads the TXT values at `fqdn` straight from the server, over TCP.
async fn txt_values(fqdn: &str) -> Vec<String> {
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_ascii(format!("{fqdn}.")).unwrap(),
        RecordType::TXT,
    ));
    let request = query.to_vec().unwrap();

    let mut stream = TcpStream::connect(NAMESERVER).await.unwrap();
    let mut framed = (request.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&request);
    stream.write_all(&framed).await.unwrap();
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.unwrap();
    let mut response = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut response).await.unwrap();

    let mut values: Vec<String> = Message::from_vec(&response)
        .unwrap()
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|data| String::from_utf8(data.to_vec()).unwrap())
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect();
    values.sort();
    values
}

#[tokio::test]
#[ignore = "requires BIND (scripts/bind-up.sh)"]
async fn present_and_cleanup_keep_other_values() {
    let fqdn = "_acme-challenge.both.example.com";
    let provider = provider(SHA256_KEY, SHA256_SECRET, TsigAlgorithm::HmacSha256);

    provider.present(fqdn, VALUE).await.unwrap();
    provider.present(fqdn, OTHER_VALUE).await.unwrap();
    // Idempotent: adding a value already present is a no-op.
    provider.present(fqdn, VALUE).await.unwrap();
    assert_eq!(txt_values(fqdn).await, vec![VALUE, OTHER_VALUE]);

    provider.cleanup(fqdn, VALUE).await.unwrap();
    assert_eq!(txt_values(fqdn).await, vec![OTHER_VALUE]);

    provider.cleanup(fqdn, OTHER_VALUE).await.unwrap();
    assert!(txt_values(fqdn).await.is_empty());

    // Removing a value that is gone is not an error.
    provider.cleanup(fqdn, OTHER_VALUE).await.unwrap();
}

#[tokio::test]
#[ignore = "requires BIND (scripts/bind-up.sh)"]
async fn hmac_sha512_key_is_accepted() {
    let fqdn = "_acme-challenge.sha512.example.com";
    let provider = provider(SHA512_KEY, SHA512_SECRET, TsigAlgorithm::HmacSha512);

    provider.present(fqdn, VALUE).await.unwrap();
    assert_eq!(txt_values(fqdn).await, vec![VALUE]);
    provider.cleanup(fqdn, VALUE).await.unwrap();
    assert!(txt_values(fqdn).await.is_empty());
}

#[tokio::test]
#[ignore = "requires BIND (scripts/bind-up.sh)"]
async fn wrong_secret_is_rejected() {
    let provider = provider(SHA256_KEY, SHA512_SECRET, TsigAlgorithm::HmacSha256);

    let err = provider
        .present("_acme-challenge.badsig.example.com", VALUE)
        .await
        .unwrap_err();

    assert!(matches!(err, DnsError::Auth(_)), "got {err:?}");
    assert!(err.to_string().contains("bad signature"), "got {err}");
}

#[tokio::test]
#[ignore = "requires BIND (scripts/bind-up.sh)"]
async fn unknown_key_is_rejected() {
    let provider = provider("no-such-key", SHA256_SECRET, TsigAlgorithm::HmacSha256);

    let err = provider
        .present("_acme-challenge.badkey.example.com", VALUE)
        .await
        .unwrap_err();

    assert!(matches!(err, DnsError::Auth(_)), "got {err:?}");
    assert!(err.to_string().contains("unknown key"), "got {err}");
}

#[tokio::test]
#[ignore = "requires BIND (scripts/bind-up.sh)"]
async fn update_outside_policy_is_refused() {
    // The update-policy only grants TXT under the zone; an fqdn in another
    // zone the server is not primary for is answered NOTAUTH.
    let config = Rfc2136Config::new(NAMESERVER, SHA256_KEY, SHA256_SECRET)
        .with_zone("example.org")
        .unwrap();
    let provider = Rfc2136Provider::new(config).unwrap();

    let err = provider
        .present("_acme-challenge.example.org", VALUE)
        .await
        .unwrap_err();

    assert!(matches!(err, DnsError::Auth(_)), "got {err:?}");
    // BIND signs this error, so it must not be flagged as unauthenticated.
    assert!(!err.to_string().contains("not authenticated"), "got {err}");
}

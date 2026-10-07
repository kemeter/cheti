//! Drives `Rfc2136Provider` against an in-process TCP server that verifies
//! the TSIG signature of each UPDATE, applies it to an in-memory TXT store
//! following RFC 2136 semantics, and answers with a signed response.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cheti::{DnsError, DnsProvider, Rfc2136Config, Rfc2136Provider, TsigAlgorithm};
use hickory_proto::op::{Message, OpCode, ResponseCode, UpdateMessage};
use hickory_proto::rr::rdata::tsig::TsigAlgorithm as HickoryTsigAlgorithm;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType, TSigResponseContext, TSigner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const ZONE: &str = "example.com";
const FQDN: &str = "_acme-challenge.example.com";
const VALUE: &str = "abcDEF123_-token_for_acme";
const OTHER_VALUE: &str = "previously-placed-value-xyz";
const KEY_NAME: &str = "acme-update";
// base64("cheti-test-secret-for-tsig-hmac!!")
const SECRET: &str = "Y2hldGktdGVzdC1zZWNyZXQtZm9yLXRzaWctaG1hYyEh";
const WRONG_SECRET: &str = "d3Jvbmctc2VjcmV0";

#[derive(Clone, Copy)]
enum Behavior {
    /// Verify, apply and sign the response like a real primary server.
    Normal,
    /// Answer every update with this RCODE (signed).
    Rcode(ResponseCode),
    /// Sign the response with a key the client does not share.
    ForgedResponse,
    /// Accept the connection but never answer.
    Silent,
}

/// What the mock server observed and stored.
#[derive(Default)]
struct State {
    /// Owner name → TXT values.
    txt: HashMap<String, BTreeSet<String>>,
    /// Requests whose TSIG signature verified.
    updates: Vec<Message>,
}

struct MockServer {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl MockServer {
    async fn start(behavior: Behavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let state = shared.clone();
                tokio::spawn(async move {
                    serve(stream, behavior, state).await;
                });
            }
        });
        Self { addr, state }
    }

    fn values(&self, owner: &str) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state
            .txt
            .get(owner)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn updates(&self) -> Vec<Message> {
        self.state.lock().unwrap().updates.clone()
    }

    fn seed(&self, owner: &str, value: &str) {
        let mut state = self.state.lock().unwrap();
        state
            .txt
            .entry(owner.to_string())
            .or_default()
            .insert(value.to_string());
    }

    fn provider(&self, secret: &str) -> Rfc2136Provider {
        let config = Rfc2136Config::new(self.addr.to_string(), KEY_NAME, secret)
            .with_zone(ZONE)
            .unwrap()
            .with_timeout(Duration::from_secs(2));
        Rfc2136Provider::new(config).unwrap()
    }
}

fn server_signer(secret: &str) -> TSigner {
    TSigner::new(
        data_encoding::BASE64.decode(secret.as_bytes()).unwrap(),
        HickoryTsigAlgorithm::HmacSha256,
        Name::from_ascii(KEY_NAME).unwrap(),
        300,
    )
    .unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn serve(mut stream: TcpStream, behavior: Behavior, state: Arc<Mutex<State>>) {
    let mut len = [0u8; 2];
    if stream.read_exact(&mut len).await.is_err() {
        return;
    }
    let mut request = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut request).await.unwrap();

    if let Behavior::Silent = behavior {
        tokio::time::sleep(Duration::from_secs(30)).await;
        return;
    }

    let message = Message::from_vec(&request).unwrap();
    let signer = server_signer(SECRET);
    let response_bytes = match signer.verify_message_byte(&request, None, true) {
        Err(_) => {
            // RFC 8945 §5.2.2: NOTAUTH with BADSIG, unsigned.
            let mut response =
                Message::error_msg(message.id, OpCode::Update, ResponseCode::NotAuth);
            let unsigned = response.to_vec().unwrap();
            let tsig = TSigResponseContext::bad_signature(message.id, now(), signer)
                .sign(&unsigned)
                .unwrap();
            response.set_signature(tsig);
            response.to_vec().unwrap()
        }
        Ok((request_mac, _, _)) => {
            let rcode = match behavior {
                Behavior::Rcode(rcode) => rcode,
                _ => ResponseCode::NoError,
            };
            {
                let mut state = state.lock().unwrap();
                if rcode == ResponseCode::NoError {
                    apply(&mut state, &message);
                }
                state.updates.push(message.clone());
            }
            let response_signer = match behavior {
                Behavior::ForgedResponse => server_signer(WRONG_SECRET),
                _ => signer,
            };
            let mut response = Message::error_msg(message.id, OpCode::Update, rcode);
            let unsigned = response.to_vec().unwrap();
            let tsig =
                TSigResponseContext::new(message.id, now(), response_signer, request_mac, None)
                    .sign(&unsigned)
                    .unwrap();
            response.set_signature(tsig);
            response.to_vec().unwrap()
        }
    };

    let mut framed = (response_bytes.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&response_bytes);
    stream.write_all(&framed).await.unwrap();
}

/// Applies the update section (RFC 2136 §3.4.2) to the TXT store.
fn apply(state: &mut State, message: &Message) {
    for record in message.updates() {
        let owner = record.name.to_ascii().trim_end_matches('.').to_string();
        let set = state.txt.entry(owner).or_default();
        match (record.dns_class, &record.data) {
            (DNSClass::IN, RData::TXT(txt)) => {
                for data in txt.txt_data.iter() {
                    set.insert(String::from_utf8(data.to_vec()).unwrap());
                }
            }
            (DNSClass::NONE, RData::TXT(txt)) => {
                for data in txt.txt_data.iter() {
                    set.remove(&String::from_utf8(data.to_vec()).unwrap());
                }
            }
            (DNSClass::ANY, _) => {
                set.clear();
            }
            other => panic!("unexpected update record {other:?}"),
        }
    }
}

#[tokio::test]
async fn present_adds_txt_value_with_signed_update() {
    let server = MockServer::start(Behavior::Normal).await;
    server.provider(SECRET).present(FQDN, VALUE).await.unwrap();

    assert_eq!(server.values(FQDN), vec![VALUE.to_string()]);

    let updates = server.updates();
    assert_eq!(updates.len(), 1);
    let update = &updates[0];
    assert_eq!(update.op_code, OpCode::Update);
    assert_eq!(
        update.zones()[0].name(),
        &Name::from_ascii("example.com.").unwrap()
    );
    assert_eq!(update.zones()[0].query_type(), RecordType::SOA);
    assert!(update.prerequisites().is_empty());
    assert_eq!(update.updates().len(), 1);
    assert_eq!(update.updates()[0].ttl, 60);
    let signature = update.signature.as_ref().unwrap();
    assert_eq!(signature.name, Name::from_ascii("acme-update.").unwrap());
}

#[tokio::test]
async fn present_keeps_values_already_on_the_name() {
    // Wildcard and apex issuance put two values on the same name.
    let server = MockServer::start(Behavior::Normal).await;
    server.seed(FQDN, OTHER_VALUE);

    server.provider(SECRET).present(FQDN, VALUE).await.unwrap();

    assert_eq!(
        server.values(FQDN),
        vec![VALUE.to_string(), OTHER_VALUE.to_string()]
    );
}

#[tokio::test]
async fn cleanup_removes_only_its_own_value() {
    let server = MockServer::start(Behavior::Normal).await;
    let provider = server.provider(SECRET);
    provider.present(FQDN, VALUE).await.unwrap();
    provider.present(FQDN, OTHER_VALUE).await.unwrap();

    provider.cleanup(FQDN, VALUE).await.unwrap();

    assert_eq!(server.values(FQDN), vec![OTHER_VALUE.to_string()]);
    let updates = server.updates();
    let delete = &updates.last().unwrap().updates()[0];
    assert_eq!(delete.dns_class, DNSClass::NONE);
    assert_eq!(delete.ttl, 0);
}

#[tokio::test]
async fn present_uses_configured_ttl_and_apex_name() {
    let server = MockServer::start(Behavior::Normal).await;
    let config = Rfc2136Config::new(server.addr.to_string(), KEY_NAME, SECRET)
        .with_zone(ZONE)
        .unwrap()
        .with_ttl(300)
        .unwrap();
    let provider = Rfc2136Provider::new(config).unwrap();

    provider.present(ZONE, VALUE).await.unwrap();

    assert_eq!(server.values(ZONE), vec![VALUE.to_string()]);
    assert_eq!(server.updates()[0].updates()[0].ttl, 300);
}

#[tokio::test]
async fn wrong_secret_is_reported_as_auth_error() {
    let server = MockServer::start(Behavior::Normal).await;

    let err = server
        .provider(WRONG_SECRET)
        .present(FQDN, VALUE)
        .await
        .unwrap_err();

    assert!(matches!(err, DnsError::Auth(_)), "got {err:?}");
    assert!(err.to_string().contains("bad signature"), "got {err}");
    assert!(server.values(FQDN).is_empty());
}

#[tokio::test]
async fn refused_update_is_reported_as_auth_error() {
    let server = MockServer::start(Behavior::Rcode(ResponseCode::Refused)).await;

    let err = server
        .provider(SECRET)
        .present(FQDN, VALUE)
        .await
        .unwrap_err();

    assert!(matches!(err, DnsError::Auth(_)), "got {err:?}");
}

#[tokio::test]
async fn server_failure_is_reported_as_api_error() {
    let server = MockServer::start(Behavior::Rcode(ResponseCode::ServFail)).await;

    let err = server
        .provider(SECRET)
        .cleanup(FQDN, VALUE)
        .await
        .unwrap_err();

    assert!(matches!(err, DnsError::Api(_)), "got {err:?}");
}

#[tokio::test]
async fn response_with_bad_signature_is_rejected() {
    let server = MockServer::start(Behavior::ForgedResponse).await;

    let err = server
        .provider(SECRET)
        .present(FQDN, VALUE)
        .await
        .unwrap_err();

    assert!(matches!(err, DnsError::Auth(_)), "got {err:?}");
    assert!(err.to_string().contains("TSIG verification"), "got {err}");
}

#[tokio::test]
async fn silent_server_times_out() {
    let server = MockServer::start(Behavior::Silent).await;
    let config = Rfc2136Config::new(server.addr.to_string(), KEY_NAME, SECRET)
        .with_zone(ZONE)
        .unwrap()
        .with_timeout(Duration::from_millis(200));
    let provider = Rfc2136Provider::new(config).unwrap();

    let started = std::time::Instant::now();
    let err = provider.present(FQDN, VALUE).await.unwrap_err();

    assert!(err.to_string().contains("timed out"), "got {err}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn fqdn_outside_zone_is_rejected_before_sending() {
    let server = MockServer::start(Behavior::Normal).await;

    let err = server
        .provider(SECRET)
        .present("_acme-challenge.other.org", VALUE)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("not within zone"), "got {err}");
    assert!(server.updates().is_empty());
}

#[tokio::test]
async fn algorithm_mismatch_is_reported_as_auth_error() {
    // The mock only knows the key as hmac-sha256, so a hmac-sha512 signature
    // must be rejected: the configured algorithm reaches the wire.
    let server = MockServer::start(Behavior::Normal).await;
    let config = Rfc2136Config::new(server.addr.to_string(), KEY_NAME, SECRET)
        .with_zone(ZONE)
        .unwrap()
        .with_algorithm(TsigAlgorithm::HmacSha512);
    let provider = Rfc2136Provider::new(config).unwrap();

    let err = provider.present(FQDN, VALUE).await.unwrap_err();

    assert!(matches!(err, DnsError::Auth(_)), "got {err:?}");
}

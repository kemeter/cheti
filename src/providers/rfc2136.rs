//! Generic provider speaking RFC 2136 dynamic updates, authenticated with
//! TSIG (RFC 8945). Works with any primary server that accepts signed
//! updates: BIND, Knot DNS, PowerDNS, and others.

use std::env;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use data_encoding::BASE64;
use hickory_proto::op::update_message::{append, delete_by_rdata};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::tsig::{TsigAlgorithm as HickoryTsigAlgorithm, TsigError};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{Name, RData, Record, RecordSet, TSigVerifier, TSigner};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::dns::find_zone;
use crate::error::DnsError;
use crate::provider::DnsProvider;
use crate::providers::common::{validate_acme_value, validate_fqdn, validate_zone};

const ENV_NAMESERVER: &str = "RFC2136_NAMESERVER";
const ENV_TSIG_KEY: &str = "RFC2136_TSIG_KEY";
const ENV_TSIG_SECRET: &str = "RFC2136_TSIG_SECRET";
const ENV_TSIG_ALGORITHM: &str = "RFC2136_TSIG_ALGORITHM";
const DEFAULT_PORT: u16 = 53;
const DEFAULT_TTL: u32 = 60;
/// RFC 2181 §8: a TTL is an unsigned number between 0 and 2^31 - 1.
const MAX_TTL: u32 = i32::MAX as u32;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Allowed clock skew between us and the server, in seconds. 300 is the
/// value recommended by RFC 8945 §10.
const TSIG_FUDGE: u16 = 300;
const PROVIDER: &str = "rfc2136";

/// HMAC algorithm used to sign updates. Must match the algorithm the key was
/// declared with on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TsigAlgorithm {
    #[default]
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithm {
    /// The algorithm name as written in server configurations, e.g. `hmac-sha256`.
    pub fn as_str(&self) -> &'static str {
        match self {
            TsigAlgorithm::HmacSha256 => "hmac-sha256",
            TsigAlgorithm::HmacSha384 => "hmac-sha384",
            TsigAlgorithm::HmacSha512 => "hmac-sha512",
        }
    }

    fn to_hickory(self) -> HickoryTsigAlgorithm {
        match self {
            TsigAlgorithm::HmacSha256 => HickoryTsigAlgorithm::HmacSha256,
            TsigAlgorithm::HmacSha384 => HickoryTsigAlgorithm::HmacSha384,
            TsigAlgorithm::HmacSha512 => HickoryTsigAlgorithm::HmacSha512,
        }
    }
}

impl fmt::Display for TsigAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TsigAlgorithm {
    type Err = DnsError;

    /// Accepts the names used by BIND and Knot (`hmac-sha256`), case
    /// insensitively and with an optional trailing dot.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim().trim_end_matches('.').to_ascii_lowercase();
        match name.as_str() {
            "hmac-sha256" => Ok(TsigAlgorithm::HmacSha256),
            "hmac-sha384" => Ok(TsigAlgorithm::HmacSha384),
            "hmac-sha512" => Ok(TsigAlgorithm::HmacSha512),
            "hmac-md5" | "hmac-md5.sig-alg.reg.int" | "hmac-sha1" | "hmac-sha224" => {
                Err(DnsError::Other(format!(
                    "unsupported TSIG algorithm {s}: use hmac-sha256, hmac-sha384 or hmac-sha512"
                )))
            }
            _ => Err(DnsError::Other(format!("unknown TSIG algorithm {s}"))),
        }
    }
}

pub struct Rfc2136Config {
    nameserver: String,
    key_name: String,
    secret: SecretString,
    algorithm: TsigAlgorithm,
    zone_override: Option<String>,
    ttl: u32,
    timeout: Duration,
}

impl Rfc2136Config {
    /// `nameserver` is the primary server accepting updates, as `host`,
    /// `host:port`, `ip`, `ip:port` or `[ipv6]:port` (port defaults to 53).
    /// `key_name` is the TSIG key name and `secret` its base64-encoded value,
    /// both as declared on the server. Values are validated by
    /// [`Rfc2136Provider::new`].
    pub fn new(
        nameserver: impl Into<String>,
        key_name: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        Self {
            nameserver: nameserver.into(),
            key_name: key_name.into(),
            secret: SecretString::new(secret.into().into()),
            algorithm: TsigAlgorithm::default(),
            zone_override: None,
            ttl: DEFAULT_TTL,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// TSIG algorithm of the key. Defaults to `hmac-sha256`.
    pub fn with_algorithm(mut self, algorithm: TsigAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Skip the SOA lookup and send updates for `zone` directly. The given
    /// fqdn must be at-or-below `zone`.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Result<Self, DnsError> {
        let zone = zone.into();
        validate_zone(&zone)?;
        self.zone_override = Some(zone);
        Ok(self)
    }

    /// TTL of the TXT records written. Defaults to 60 seconds.
    pub fn with_ttl(mut self, ttl: u32) -> Result<Self, DnsError> {
        if ttl > MAX_TTL {
            return Err(DnsError::Other(format!(
                "TTL must be at most {MAX_TTL}, got {ttl}"
            )));
        }
        self.ttl = ttl;
        Ok(self)
    }

    /// Upper bound for one update exchange (connect, send, receive).
    /// Defaults to 10 seconds.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Where updates are sent, split once at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Nameserver {
    host: String,
    port: u16,
}

impl fmt::Display for Nameserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

fn parse_nameserver(raw: &str) -> Result<Nameserver, DnsError> {
    let raw = raw.trim();
    let invalid = || DnsError::Other(format!("invalid {PROVIDER} nameserver: {raw:?}"));

    if let Ok(addr) = raw.parse::<SocketAddr>() {
        if addr.port() == 0 {
            return Err(invalid());
        }
        return Ok(Nameserver {
            host: addr.ip().to_string(),
            port: addr.port(),
        });
    }
    let unbracketed = raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Ok(Nameserver {
            host: ip.to_string(),
            port: DEFAULT_PORT,
        });
    }

    let (host, port) = match raw.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse::<u16>().map_err(|_| invalid())?;
            (host, port)
        }
        None => (raw, DEFAULT_PORT),
    };
    if port == 0 || host.contains(':') || validate_fqdn(host).is_err() {
        return Err(invalid());
    }
    Ok(Nameserver {
        host: host.trim_end_matches('.').to_string(),
        port,
    })
}

fn parse_name(raw: &str, what: &str) -> Result<Name, DnsError> {
    validate_fqdn(raw)?;
    let mut name = Name::from_ascii(raw)
        .map_err(|e| DnsError::Other(format!("invalid {what} {raw:?}: {e}")))?;
    name.set_fqdn(true);
    Ok(name)
}

fn decode_secret(secret: &SecretString) -> Result<Vec<u8>, DnsError> {
    let key = BASE64
        .decode(secret.expose_secret().trim().as_bytes())
        .map_err(|_| DnsError::Other(format!("{PROVIDER} TSIG secret is not valid base64")))?;
    if key.is_empty() {
        return Err(DnsError::Other(format!("{PROVIDER} TSIG secret is empty")));
    }
    Ok(key)
}

/// The update adding `value` to the TXT RRset at `fqdn` (RFC 2136 §2.5.1).
/// Other values of the RRset are left untouched, and adding a value already
/// present is a no-op on the server (§3.4.2.2).
fn build_present_message(zone: &Name, fqdn: &Name, value: &str, ttl: u32) -> Message {
    append(txt_rrset(fqdn, value, ttl), zone.clone(), false, false)
}

/// The update deleting only `value` from the TXT RRset at `fqdn`
/// (RFC 2136 §2.5.4). Ignored by the server when the value is absent.
fn build_cleanup_message(zone: &Name, fqdn: &Name, value: &str) -> Message {
    delete_by_rdata(txt_rrset(fqdn, value, 0), zone.clone(), false)
}

fn txt_rrset(fqdn: &Name, value: &str, ttl: u32) -> RecordSet {
    let rdata = RData::TXT(TXT::new(vec![value.to_string()]));
    RecordSet::from(Record::from_rdata(fqdn.clone(), ttl, rdata))
}

/// Checks a raw response against the signed request it answers. Errors are
/// read before the signature, since servers answer BADKEY and BADSIG with
/// unsigned responses (RFC 8945 §5.3.2). Any other error is expected to be
/// signed and verifiable: one that is not is still reported, but flagged as
/// unauthenticated, as nothing proves the server sent it.
fn check_response(
    request_id: u16,
    bytes: &[u8],
    verifier: &mut TSigVerifier,
    nameserver: &Nameserver,
) -> Result<(), DnsError> {
    let response = Message::from_vec(bytes).map_err(|e| {
        DnsError::Api(format!(
            "{PROVIDER} malformed response from {nameserver}: {e}"
        ))
    })?;
    if response.id != request_id
        || response.message_type != MessageType::Response
        || response.op_code != OpCode::Update
    {
        return Err(DnsError::Api(format!(
            "{PROVIDER} unexpected response from {nameserver}: not an answer to our update"
        )));
    }

    let rcode = response.response_code;
    if rcode != ResponseCode::NoError {
        let tsig_error = response.signature.as_ref().and_then(|sig| sig.data.error);
        // NOTAUTH with BADKEY or BADSIG comes unsigned, and BADTIME carries the
        // server's clock, which fails the time check (RFC 8945 §5.3.2): those
        // cannot be verified by design. Any other error must be.
        let unverifiable_by_design = rcode == ResponseCode::NotAuth
            && matches!(
                tsig_error,
                Some(TsigError::BadKey | TsigError::BadSig | TsigError::BadTime)
            );
        let unverified = if unverifiable_by_design || verifier.verify(bytes).is_ok() {
            None
        } else if response.signature.is_none() {
            Some("unsigned response")
        } else {
            Some("TSIG verification failed")
        };
        return Err(rcode_error(rcode, tsig_error, unverified, nameserver));
    }

    verifier.verify(bytes).map_err(|e| {
        DnsError::Auth(format!(
            "{PROVIDER} response from {nameserver} failed TSIG verification: {e}"
        ))
    })?;
    Ok(())
}

fn rcode_error(
    rcode: ResponseCode,
    tsig_error: Option<TsigError>,
    unverified: Option<&str>,
    nameserver: &Nameserver,
) -> DnsError {
    let detail = match tsig_error {
        Some(TsigError::BadSig) => " (TSIG: bad signature, check the secret and algorithm)",
        Some(TsigError::BadKey) => " (TSIG: unknown key, check the key name and algorithm)",
        Some(TsigError::BadTime) => " (TSIG: clock skew too large between client and server)",
        Some(_) => " (TSIG error)",
        None => "",
    };
    let unverified = match unverified {
        Some(reason) => format!(" ({reason}, not authenticated)"),
        None => String::new(),
    };
    let message =
        format!("{PROVIDER} update rejected by {nameserver}: {rcode}{detail}{unverified}");
    match rcode {
        ResponseCode::NotAuth | ResponseCode::Refused => DnsError::Auth(message),
        _ => DnsError::Api(message),
    }
}

fn unix_now() -> Result<u64, DnsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| DnsError::Other("system clock is before the Unix epoch".into()))
}

pub struct Rfc2136Provider {
    config: Rfc2136Config,
    nameserver: Nameserver,
    key_name: Name,
}

impl Rfc2136Provider {
    pub fn new(config: Rfc2136Config) -> Result<Self, DnsError> {
        let nameserver = parse_nameserver(&config.nameserver)?;
        let key_name = parse_name(&config.key_name, "TSIG key name")?;
        decode_secret(&config.secret)?;
        Ok(Self {
            config,
            nameserver,
            key_name,
        })
    }

    /// Reads `RFC2136_NAMESERVER`, `RFC2136_TSIG_KEY`, `RFC2136_TSIG_SECRET`
    /// and, optionally, `RFC2136_TSIG_ALGORITHM` (defaults to `hmac-sha256`).
    pub fn from_env() -> Result<Self, DnsError> {
        let nameserver = env::var(ENV_NAMESERVER)
            .map_err(|_| DnsError::MissingCredentials(ENV_NAMESERVER.into()))?;
        let key_name = env::var(ENV_TSIG_KEY)
            .map_err(|_| DnsError::MissingCredentials(ENV_TSIG_KEY.into()))?;
        let secret = env::var(ENV_TSIG_SECRET)
            .map_err(|_| DnsError::MissingCredentials(ENV_TSIG_SECRET.into()))?;
        let mut config = Rfc2136Config::new(nameserver, key_name, secret);
        if let Ok(algorithm) = env::var(ENV_TSIG_ALGORITHM) {
            config = config.with_algorithm(algorithm.parse()?);
        }
        Self::new(config)
    }

    /// Built per update, so the decoded key only lives as long as one exchange.
    fn signer(&self) -> Result<TSigner, DnsError> {
        let key = decode_secret(&self.config.secret)?;
        TSigner::new(
            key,
            self.config.algorithm.to_hickory(),
            self.key_name.clone(),
            TSIG_FUDGE,
        )
        .map_err(|e| DnsError::Other(format!("{PROVIDER} TSIG signer: {e}")))
    }

    async fn resolve_zone(&self, fqdn: &str) -> Result<String, DnsError> {
        match &self.config.zone_override {
            Some(z) => Ok(z.clone()),
            None => {
                let zone = find_zone(fqdn).await?;
                validate_fqdn(&zone)?;
                Ok(zone)
            }
        }
    }

    /// Resolves the zone owning `fqdn` and checks that `fqdn` lies within it.
    async fn names(&self, fqdn: &str) -> Result<(Name, Name), DnsError> {
        let zone = parse_name(&self.resolve_zone(fqdn).await?, "zone")?;
        let name = parse_name(fqdn, "fqdn")?;
        if !zone.zone_of(&name) {
            return Err(DnsError::Other(format!(
                "fqdn {fqdn} is not within zone {zone}"
            )));
        }
        Ok((zone, name))
    }

    async fn send_update(&self, mut message: Message) -> Result<(), DnsError> {
        let signer = self.signer()?;
        let mut verifier = message
            .finalize(&signer, unix_now()?)
            .map_err(|e| DnsError::Other(format!("{PROVIDER} signing update: {e}")))?
            .ok_or_else(|| DnsError::Other(format!("{PROVIDER} signing update: no verifier")))?;
        let request = message
            .to_vec()
            .map_err(|e| DnsError::Other(format!("{PROVIDER} encoding update: {e}")))?;

        let response = tokio::time::timeout(self.config.timeout, self.exchange(&request))
            .await
            .map_err(|_| {
                DnsError::Api(format!(
                    "{PROVIDER} update to {} timed out after {:?}",
                    self.nameserver, self.config.timeout
                ))
            })??;

        check_response(message.id, &response, &mut verifier, &self.nameserver)
    }

    /// One request/response over TCP, each prefixed by its two-byte length
    /// (RFC 1035 §4.2.2).
    async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, DnsError> {
        let io_error = |e: std::io::Error| {
            DnsError::Api(format!("{PROVIDER} exchange with {}: {e}", self.nameserver))
        };
        let length = u16::try_from(request.len())
            .map_err(|_| DnsError::Other(format!("{PROVIDER} update message too large")))?;
        let mut framed = Vec::with_capacity(request.len() + 2);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(request);

        let mut stream = TcpStream::connect((self.nameserver.host.as_str(), self.nameserver.port))
            .await
            .map_err(io_error)?;
        stream.write_all(&framed).await.map_err(io_error)?;

        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.map_err(io_error)?;
        let mut response = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut response).await.map_err(io_error)?;
        Ok(response)
    }
}

#[async_trait]
impl DnsProvider for Rfc2136Provider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        validate_acme_value(value)?;
        let (zone, name) = self.names(fqdn).await?;
        self.send_update(build_present_message(&zone, &name, value, self.config.ttl))
            .await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        validate_fqdn(fqdn)?;
        let (zone, name) = self.names(fqdn).await?;
        self.send_update(build_cleanup_message(&zone, &name, value))
            .await
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::UpdateMessage;
    use hickory_proto::rr::{DNSClass, RecordType};

    use super::*;

    const SECRET: &str = "c2VjcmV0LWtleS1mb3ItdGVzdHMtb25seQ==";

    fn ns(host: &str, port: u16) -> Nameserver {
        Nameserver {
            host: host.to_string(),
            port,
        }
    }

    fn name(s: &str) -> Name {
        parse_name(s, "test").unwrap()
    }

    #[test]
    fn parse_nameserver_accepts_ip_with_and_without_port() {
        assert_eq!(parse_nameserver("192.0.2.1").unwrap(), ns("192.0.2.1", 53));
        assert_eq!(
            parse_nameserver("192.0.2.1:5353").unwrap(),
            ns("192.0.2.1", 5353)
        );
    }

    #[test]
    fn parse_nameserver_accepts_ipv6_forms() {
        assert_eq!(
            parse_nameserver("2001:db8::1").unwrap(),
            ns("2001:db8::1", 53)
        );
        assert_eq!(
            parse_nameserver("[2001:db8::1]").unwrap(),
            ns("2001:db8::1", 53)
        );
        assert_eq!(
            parse_nameserver("[2001:db8::1]:5353").unwrap(),
            ns("2001:db8::1", 5353)
        );
    }

    #[test]
    fn parse_nameserver_accepts_hostname() {
        assert_eq!(
            parse_nameserver("ns1.example.com").unwrap(),
            ns("ns1.example.com", 53)
        );
        assert_eq!(
            parse_nameserver("ns1.example.com.:5353").unwrap(),
            ns("ns1.example.com", 5353)
        );
    }

    #[test]
    fn parse_nameserver_rejects_invalid() {
        assert!(parse_nameserver("").is_err());
        assert!(parse_nameserver("ns1.example.com:").is_err());
        assert!(parse_nameserver("ns1.example.com:0").is_err());
        assert!(parse_nameserver("ns1.example.com:99999").is_err());
        assert!(parse_nameserver("192.0.2.1:0").is_err());
        assert!(parse_nameserver("foo..bar").is_err());
    }

    #[test]
    fn nameserver_display_brackets_ipv6() {
        assert_eq!(ns("2001:db8::1", 53).to_string(), "[2001:db8::1]:53");
        assert_eq!(ns("192.0.2.1", 53).to_string(), "192.0.2.1:53");
    }

    #[test]
    fn algorithm_parses_server_names() {
        assert_eq!(
            "hmac-sha256".parse::<TsigAlgorithm>().unwrap(),
            TsigAlgorithm::HmacSha256
        );
        assert_eq!(
            "HMAC-SHA512.".parse::<TsigAlgorithm>().unwrap(),
            TsigAlgorithm::HmacSha512
        );
        assert_eq!(
            "hmac-sha384".parse::<TsigAlgorithm>().unwrap(),
            TsigAlgorithm::HmacSha384
        );
    }

    #[test]
    fn algorithm_rejects_unsupported_and_unknown() {
        let err = "hmac-sha1".parse::<TsigAlgorithm>().unwrap_err();
        assert!(err.to_string().contains("unsupported"), "got {err}");
        assert!("hmac-md5".parse::<TsigAlgorithm>().is_err());
        assert!("sha256".parse::<TsigAlgorithm>().is_err());
    }

    #[test]
    fn algorithm_round_trips_through_display() {
        for alg in [
            TsigAlgorithm::HmacSha256,
            TsigAlgorithm::HmacSha384,
            TsigAlgorithm::HmacSha512,
        ] {
            assert_eq!(alg.to_string().parse::<TsigAlgorithm>().unwrap(), alg);
        }
    }

    #[test]
    fn new_accepts_valid_config() {
        let cfg = Rfc2136Config::new("192.0.2.1", "acme-key", SECRET);
        assert!(Rfc2136Provider::new(cfg).is_ok());
    }

    #[test]
    fn new_rejects_invalid_secret() {
        let cfg = Rfc2136Config::new("192.0.2.1", "acme-key", "not base64!");
        assert!(Rfc2136Provider::new(cfg).is_err());
        let cfg = Rfc2136Config::new("192.0.2.1", "acme-key", "");
        assert!(Rfc2136Provider::new(cfg).is_err());
    }

    #[test]
    fn new_rejects_invalid_key_name_and_nameserver() {
        let cfg = Rfc2136Config::new("192.0.2.1", "bad..key", SECRET);
        assert!(Rfc2136Provider::new(cfg).is_err());
        let cfg = Rfc2136Config::new("", "acme-key", SECRET);
        assert!(Rfc2136Provider::new(cfg).is_err());
    }

    #[test]
    fn with_zone_rejects_single_label() {
        let cfg = Rfc2136Config::new("192.0.2.1", "acme-key", SECRET);
        assert!(cfg.with_zone("localhost").is_err());
    }

    #[test]
    fn with_ttl_enforces_rfc2181_bound() {
        let cfg = Rfc2136Config::new("192.0.2.1", "acme-key", SECRET);
        assert!(cfg.with_ttl(u32::MAX).is_err());
        let cfg = Rfc2136Config::new("192.0.2.1", "acme-key", SECRET);
        assert_eq!(cfg.with_ttl(120).unwrap().ttl, 120);
    }

    #[test]
    fn present_message_adds_a_single_txt_rr() {
        let zone = name("example.com");
        let fqdn = name("_acme-challenge.example.com");
        let message = build_present_message(&zone, &fqdn, "token-value", 60);

        assert_eq!(message.op_code, OpCode::Update);
        assert_eq!(message.zones().len(), 1);
        assert_eq!(message.zones()[0].name(), &zone);
        assert_eq!(message.zones()[0].query_type(), RecordType::SOA);
        assert_eq!(message.zones()[0].query_class(), DNSClass::IN);
        assert!(message.prerequisites().is_empty());

        let updates = message.updates();
        assert_eq!(updates.len(), 1);
        let record = &updates[0];
        assert_eq!(record.name, fqdn);
        assert_eq!(record.dns_class, DNSClass::IN);
        assert_eq!(record.ttl, 60);
        let RData::TXT(txt) = &record.data else {
            panic!("expected TXT, got {:?}", record.data);
        };
        assert_eq!(txt.txt_data.len(), 1);
        assert_eq!(&*txt.txt_data[0], b"token-value");
    }

    #[test]
    fn cleanup_message_deletes_only_the_given_value() {
        let zone = name("example.com");
        let fqdn = name("_acme-challenge.example.com");
        let message = build_cleanup_message(&zone, &fqdn, "token-value");

        assert_eq!(message.op_code, OpCode::Update);
        assert_eq!(message.zones()[0].name(), &zone);
        let updates = message.updates();
        assert_eq!(updates.len(), 1);
        let record = &updates[0];
        // CLASS NONE with RDATA deletes one RR; CLASS ANY would drop the RRset.
        assert_eq!(record.dns_class, DNSClass::NONE);
        assert_eq!(record.ttl, 0);
        assert_eq!(record.record_type(), RecordType::TXT);
        let RData::TXT(txt) = &record.data else {
            panic!("expected TXT, got {:?}", record.data);
        };
        assert_eq!(&*txt.txt_data[0], b"token-value");
    }

    #[test]
    fn signed_update_verifies_with_the_same_key_only() {
        let provider =
            Rfc2136Provider::new(Rfc2136Config::new("192.0.2.1", "acme-key", SECRET)).unwrap();
        let mut message = build_present_message(
            &name("example.com"),
            &name("_acme-challenge.example.com"),
            "token-value",
            60,
        );
        let now = unix_now().unwrap();
        message.finalize(&provider.signer().unwrap(), now).unwrap();
        let bytes = message.to_vec().unwrap();

        let signature = message.signature.as_ref().unwrap();
        assert_eq!(signature.name, name("acme-key"));
        assert_eq!(signature.data.algorithm, HickoryTsigAlgorithm::HmacSha256);
        assert_eq!(signature.data.fudge, TSIG_FUDGE);

        let server = TSigner::new(
            BASE64.decode(SECRET.as_bytes()).unwrap(),
            HickoryTsigAlgorithm::HmacSha256,
            name("acme-key"),
            TSIG_FUDGE,
        )
        .unwrap();
        let (_, time, window) = server.verify_message_byte(&bytes, None, true).unwrap();
        assert_eq!(time, now);
        assert!(window.contains(&now));

        let other = TSigner::new(
            b"another-key".to_vec(),
            HickoryTsigAlgorithm::HmacSha256,
            name("acme-key"),
            TSIG_FUDGE,
        )
        .unwrap();
        assert!(other.verify_message_byte(&bytes, None, true).is_err());
    }

    #[test]
    fn signer_uses_configured_algorithm() {
        let cfg = Rfc2136Config::new("192.0.2.1", "acme-key", SECRET)
            .with_algorithm(TsigAlgorithm::HmacSha512);
        let provider = Rfc2136Provider::new(cfg).unwrap();
        assert_eq!(
            provider.signer().unwrap().algorithm(),
            &HickoryTsigAlgorithm::HmacSha512
        );
    }

    #[test]
    fn rcode_error_maps_auth_failures() {
        let server = ns("192.0.2.1", 53);
        let err = rcode_error(
            ResponseCode::NotAuth,
            Some(TsigError::BadKey),
            None,
            &server,
        );
        assert!(matches!(err, DnsError::Auth(_)), "got {err:?}");
        assert!(err.to_string().contains("unknown key"), "got {err}");
        let err = rcode_error(ResponseCode::Refused, None, None, &server);
        assert!(matches!(err, DnsError::Auth(_)), "got {err:?}");
        let err = rcode_error(ResponseCode::ServFail, None, None, &server);
        assert!(matches!(err, DnsError::Api(_)), "got {err:?}");
    }
}

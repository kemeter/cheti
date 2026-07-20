//! ACME TLS-ALPN-01 challenge solving (RFC 8737).
//!
//! The validator opens a TLS connection on port 443 with SNI set to the
//! domain and ALPN offering only `acme-tls/1`, then inspects the self-signed
//! certificate the server presents: it must carry the `id-pe-acmeIdentifier`
//! extension holding the SHA-256 of the key authorization. No application
//! request is ever made — the whole proof lives in the handshake.
//!
//! This module drives the ACME order and builds that challenge certificate.
//! It does not serve TLS itself: presenting the certificate on `acme-tls/1`
//! (and pulling it back down afterwards) is delegated to a [`ChallengeResponder`],
//! because how the certificate reaches port 443 is the consumer's architecture,
//! not this library's.
//!
//! ```no_run
//! use cheti::tls_alpn::{TlsAlpn01Solver, ChallengeResponder};
//! # async fn run<R: ChallengeResponder>(order: instant_acme::Order, responder: R)
//! #   -> Result<(), cheti::DnsError> {
//! let solver = TlsAlpn01Solver::new(responder);
//! let (cert_chain_pem, key_pem) = solver.solve_and_finalize(order).await?;
//! # Ok(()) }
//! ```

use async_trait::async_trait;
use instant_acme::{
    AuthorizationStatus, ChallengeType, Identifier, Order, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, CustomExtension, KeyPair};

use crate::error::DnsError;

/// The ALPN protocol identifier a TLS-ALPN-01 validator negotiates. A server
/// presenting the challenge certificate must accept exactly this protocol.
pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

/// Presents (and later removes) a TLS-ALPN-01 challenge certificate for a
/// domain. The library builds the certificate; the implementer arranges for it
/// to be served on `acme-tls/1` connections whose SNI is `domain`.
///
/// `cert_der` and `key_der` are DER-encoded — the form rustls consumes to build
/// a `CertifiedKey` — so the responder can install them without re-parsing PEM.
///
/// Named for symmetry with [`crate::DnsProvider`]; the `DnsError` return type is
/// shared across both challenge flows and is not DNS-specific here.
#[async_trait]
pub trait ChallengeResponder: Send + Sync {
    /// Serve `cert_der`/`key_der` for TLS-ALPN-01 handshakes to `domain`.
    async fn present(
        &self,
        domain: &str,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<(), DnsError>;

    /// Stop serving the challenge certificate for `domain`.
    async fn cleanup(&self, domain: &str) -> Result<(), DnsError>;
}

/// A self-signed TLS-ALPN-01 challenge certificate, DER-encoded.
#[derive(Debug, Clone)]
pub struct ChallengeCertificate {
    /// The certificate, DER-encoded.
    pub cert_der: Vec<u8>,
    /// Its private key, DER-encoded (PKCS#8).
    pub key_der: Vec<u8>,
}

/// Build the self-signed challenge certificate for `domain` from a key
/// authorization digest, per RFC 8737 §3.
///
/// `key_auth_digest` is the SHA-256 of the challenge's key authorization — 32
/// bytes, exactly what `instant_acme::KeyAuthorization::digest()` yields. The
/// certificate carries a single `dNSName` SAN equal to `domain` and a critical
/// `id-pe-acmeIdentifier` extension wrapping the digest in an `OCTET STRING`;
/// `rcgen::CustomExtension::new_acme_identifier` handles the OID, wrapping and
/// criticality.
///
/// Returns an error if the digest is not 32 bytes, or if certificate generation
/// fails.
pub fn build_challenge_certificate(
    domain: &str,
    key_auth_digest: &[u8],
) -> Result<ChallengeCertificate, DnsError> {
    if key_auth_digest.len() != 32 {
        return Err(DnsError::Other(format!(
            "TLS-ALPN-01 key authorization digest must be 32 bytes, got {}",
            key_auth_digest.len()
        )));
    }

    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| DnsError::Other(format!("challenge cert params for {domain}: {e}")))?;
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(key_auth_digest));

    let key_pair = KeyPair::generate()
        .map_err(|e| DnsError::Other(format!("challenge key generation: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| DnsError::Other(format!("challenge cert self-sign: {e}")))?;

    Ok(ChallengeCertificate {
        cert_der: cert.der().to_vec(),
        key_der: key_pair.serialize_der(),
    })
}

/// Drives an ACME order through the TLS-ALPN-01 challenge to a certificate,
/// delegating certificate presentation to a [`ChallengeResponder`].
pub struct TlsAlpn01Solver<R: ChallengeResponder> {
    responder: R,
}

impl<R: ChallengeResponder> TlsAlpn01Solver<R> {
    pub fn new(responder: R) -> Self {
        Self { responder }
    }

    /// Present each domain's challenge certificate, mark the challenges ready,
    /// then finalize the order. Returns `(certificate_chain_pem, private_key_pem)`.
    ///
    /// Presented certificates are torn down before returning, on success and on
    /// error, on a **best-effort** basis: a `cleanup` that itself fails is
    /// logged as swallowed, not surfaced, and — as with the DNS-01 solver —
    /// dropping this future mid-flight (shutdown, timeout) skips the remaining
    /// teardown. A responder that must not leak challenge material on those
    /// paths should give its presentations a short lease of their own.
    pub async fn solve_and_finalize(&self, mut order: Order) -> Result<(String, String), DnsError> {
        let presented = match self.present_all(&mut order).await {
            Ok(domains) => domains,
            Err(e) => return Err(e),
        };
        let outcome = finalize_order(&mut order).await;
        self.cleanup_all(&presented).await;
        outcome
    }

    /// Present every pending TLS-ALPN-01 challenge in the order and mark it
    /// ready. Returns the domains presented, so the caller can tear them down.
    async fn present_all(&self, order: &mut Order) -> Result<Vec<String>, DnsError> {
        // Collect the challenges first: instant_acme's authorization stream
        // borrows the order, so we can't call `set_ready` (which also borrows)
        // while iterating. Each entry is (domain, digest, challenge_url).
        let mut pending: Vec<(String, Vec<u8>, String)> = Vec::new();
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz = result.map_err(|e| DnsError::Acme(e.to_string()))?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => return Err(DnsError::ChallengeInvalid(format!("{other:?}"))),
                }

                let domain = match &authz.identifier().identifier {
                    Identifier::Dns(d) => d.clone(),
                    other => {
                        return Err(DnsError::Other(format!(
                            "unsupported identifier type: {other:?}"
                        )));
                    }
                };

                let challenge = authz.challenge(ChallengeType::TlsAlpn01).ok_or_else(|| {
                    DnsError::Other(format!("no TLS-ALPN-01 challenge for {domain}"))
                })?;
                let digest = challenge.key_authorization().digest().as_ref().to_vec();
                pending.push((domain, digest, challenge.url.clone()));
            }
        }

        let mut presented: Vec<String> = Vec::new();
        for (domain, digest, url) in pending {
            let cert = build_challenge_certificate(&domain, &digest)?;
            if let Err(e) = self
                .responder
                .present(&domain, cert.cert_der, cert.key_der)
                .await
            {
                // `present` may have installed the certificate before failing
                // (e.g. control-plane write succeeded, acknowledgement didn't),
                // so tear this domain down too — not only the earlier ones.
                let _ = self.responder.cleanup(&domain).await;
                self.cleanup_all(&presented).await;
                return Err(e);
            }
            presented.push(domain);

            if let Err(e) = set_ready_by_url(order, &url).await {
                self.cleanup_all(&presented).await;
                return Err(e);
            }
        }

        Ok(presented)
    }

    /// Best-effort teardown of every presented domain. Cleanup errors are
    /// swallowed (cheti carries no logger, matching the DNS-01 solver): the
    /// caller's outcome — the issued certificate or the primary error — is what
    /// matters, and a stale challenge certificate is inert once validation is
    /// over. A responder that needs a hard guarantee should lease its
    /// presentations rather than rely on this call.
    async fn cleanup_all(&self, domains: &[String]) {
        for domain in domains {
            let _ = self.responder.cleanup(domain).await;
        }
    }
}

/// Mark ready the TLS-ALPN-01 challenge identified by `url`. Re-iterates the
/// order because instant_acme borrows from it, so a challenge handle can't be
/// held across the earlier presentation awaits.
async fn set_ready_by_url(order: &mut Order, url: &str) -> Result<(), DnsError> {
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(|e| DnsError::Acme(e.to_string()))?;
        if let Some(mut challenge) = authz.challenge(ChallengeType::TlsAlpn01) {
            if challenge.url == url {
                return challenge
                    .set_ready()
                    .await
                    .map_err(|e| DnsError::Acme(e.to_string()));
            }
        }
    }
    Err(DnsError::Other(format!(
        "challenge {url} disappeared from order"
    )))
}

/// Poll the order to Ready, finalize it, and fetch the certificate chain.
/// Identical to the DNS-01 finalize path — the tail of an ACME order is the
/// same regardless of challenge type.
async fn finalize_order(order: &mut Order) -> Result<(String, String), DnsError> {
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| DnsError::Acme(e.to_string()))?;
    if status != OrderStatus::Ready {
        return Err(DnsError::UnexpectedOrderStatus(format!("{status:?}")));
    }

    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| DnsError::Acme(e.to_string()))?;
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| DnsError::Acme(e.to_string()))?;

    Ok((cert_chain_pem, private_key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    #[test]
    fn challenge_certificate_conforms_to_rfc8737() {
        let digest = [0xABu8; 32];
        let cert = build_challenge_certificate("example.com", &digest).unwrap();

        let (_, parsed) = X509Certificate::from_der(&cert.cert_der).unwrap();

        // Exactly one dNSName SAN, equal to the domain.
        let san = parsed
            .extensions()
            .iter()
            .find(|e| e.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .map(|e| e.parsed_extension());
        match san {
            Some(ParsedExtension::SubjectAlternativeName(san)) => {
                assert_eq!(san.general_names.len(), 1, "SAN must hold a single entry");
                assert!(
                    matches!(&san.general_names[0], GeneralName::DNSName(d) if *d == "example.com"),
                    "the single SAN entry must be the validated dNSName"
                );
            }
            _ => panic!("challenge cert is missing its subjectAltName"),
        }

        // The acmeIdentifier extension: OID 1.3.6.1.5.5.7.1.31, critical, value
        // = OCTET STRING of the digest.
        let acme_oid = der_parser::oid!(1.3.6 .1 .5 .5 .7 .1 .31);
        let ext = parsed
            .extensions()
            .iter()
            .find(|e| e.oid == acme_oid)
            .expect("challenge cert is missing the acmeIdentifier extension");
        assert!(
            ext.critical,
            "acmeIdentifier must be critical (RFC 8737 §3)"
        );

        // The value must be *exactly* an OCTET STRING of the digest: not an
        // INTEGER or other primitive carrying the same bytes, and with no
        // trailing DER after it. `ext.value` is already the extnValue content
        // (x509-parser stripped the outer X.509 wrapper).
        let (rest, inner) = der_parser::parse_der(ext.value).unwrap();
        assert!(
            rest.is_empty(),
            "no trailing bytes after the acmeIdentifier"
        );
        assert!(
            matches!(
                inner.content,
                der_parser::ber::BerObjectContent::OctetString(_)
            ),
            "acmeIdentifier must be an OCTET STRING, not another type carrying the bytes"
        );
        assert_eq!(
            inner.as_slice().unwrap(),
            digest,
            "the OCTET STRING must hold exactly the 32-byte digest"
        );
    }

    #[test]
    fn a_wrong_size_digest_is_rejected() {
        // Guards against passing something other than a SHA-256 (e.g. a raw
        // key authorization) — rcgen would otherwise panic on a bad length.
        let err = build_challenge_certificate("example.com", &[0u8; 20]).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn each_domain_gets_its_own_digest() {
        // Two domains in one order must not collide on a single certificate.
        let a = build_challenge_certificate("a.example.com", &[0x01; 32]).unwrap();
        let b = build_challenge_certificate("b.example.com", &[0x02; 32]).unwrap();
        assert_ne!(a.cert_der, b.cert_der);
    }
}

//! Decide whether an existing certificate is due for renewal.

use std::time::{SystemTime, UNIX_EPOCH};

use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::DnsError;

/// Returns `true` if the leaf certificate in `pem` expires within
/// `threshold_days` days of `now`, or has already expired.
///
/// Use this to gate a re-issuance: poll your cert store on a schedule and
/// call `solve_and_finalize` again when this returns true. Common threshold
/// for Let's Encrypt (90-day certs) is 30 days; for short-lived certs you
/// want something tighter relative to the validity window.
pub fn needs_renewal(pem: &str, threshold_days: u32) -> Result<bool, DnsError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| DnsError::Other(format!("system time before epoch: {e}")))?
        .as_secs() as i64;
    needs_renewal_at(pem, threshold_days, now)
}

/// Same as `needs_renewal`, but with an explicit `now` (Unix seconds) for
/// deterministic testing.
pub fn needs_renewal_at(pem: &str, threshold_days: u32, now_unix: i64) -> Result<bool, DnsError> {
    let leaf_der = parse_leaf_der(pem)?;
    let (_, cert): (_, X509Certificate) = X509Certificate::from_der(&leaf_der)
        .map_err(|e| DnsError::Other(format!("parse leaf certificate: {e}")))?;

    let not_after = cert.validity().not_after.timestamp();
    let threshold_seconds = i64::from(threshold_days) * 86_400;
    Ok(not_after - now_unix <= threshold_seconds)
}

fn parse_leaf_der(pem: &str) -> Result<Vec<u8>, DnsError> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    match Pem::read(&mut cursor) {
        Ok((pem, _consumed)) => {
            if pem.label != "CERTIFICATE" {
                return Err(DnsError::Other(format!(
                    "expected CERTIFICATE PEM, got {}",
                    pem.label
                )));
            }
            Ok(pem.contents)
        }
        Err(e) => Err(DnsError::Other(format!("no PEM block found: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use time::OffsetDateTime;

    /// Generate a self-signed certificate whose validity ends at `not_after_unix`.
    fn cert_pem_expiring_at(not_after_unix: i64) -> String {
        let not_after = OffsetDateTime::from_unix_timestamp(not_after_unix).unwrap();
        let not_before = not_after - time::Duration::days(365);

        let mut params = CertificateParams::new(vec!["test.example".to_string()]).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;

        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.pem()
    }

    #[test]
    fn returns_false_when_far_from_expiry() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_expiring_at(not_after);
        let now = not_after - 60 * 86_400; // 60 days before expiry
        assert!(!needs_renewal_at(&pem, 30, now).unwrap());
    }

    #[test]
    fn returns_true_when_within_threshold() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_expiring_at(not_after);
        let now = not_after - 10 * 86_400; // 10 days before expiry
        assert!(needs_renewal_at(&pem, 30, now).unwrap());
    }

    #[test]
    fn returns_true_when_already_expired() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_expiring_at(not_after);
        let now = not_after + 86_400; // 1 day after expiry
        assert!(needs_renewal_at(&pem, 30, now).unwrap());
    }

    #[test]
    fn rejects_non_pem_input() {
        let err = needs_renewal_at("not a certificate", 30, 0).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("pem"));
    }

    #[test]
    fn parses_only_leaf_when_chain_present() {
        let not_after = 1_900_000_000;
        let leaf = cert_pem_expiring_at(not_after);
        // The function should read the first cert; appending a second cert
        // (which would have different dates) shouldn't change the answer.
        let chain = format!("{leaf}{}", cert_pem_expiring_at(not_after - 365 * 86_400));
        let now = not_after - 60 * 86_400;
        assert!(!needs_renewal_at(&chain, 30, now).unwrap());
    }
}

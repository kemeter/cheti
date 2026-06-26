//! Decide whether an existing certificate is due for renewal.

use std::time::{SystemTime, UNIX_EPOCH};

use x509_parser::extensions::GeneralName;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::DnsError;

/// Returns `true` if the leaf certificate in `pem` expires within
/// `threshold_days` days of now, or has already expired — **or if the PEM
/// cannot be parsed**. An unparseable certificate is treated as "renew it",
/// because the safe failure mode for a renewal gate is to re-issue rather
/// than serve a cert you can't reason about.
///
/// Use this to gate a re-issuance: poll your cert store on a schedule and
/// call `solve_and_finalize` again when this returns true. Common threshold
/// for Let's Encrypt (90-day certs) is 30 days; for short-lived certs you
/// want something tighter relative to the validity window.
///
/// If you need to distinguish "expiring" from "unparseable", use
/// [`needs_renewal_checked`].
pub fn needs_renewal(pem: &str, threshold_days: u32) -> bool {
    needs_renewal_checked(pem, threshold_days).unwrap_or(true)
}

/// Same as [`needs_renewal`] but surfaces parse errors instead of folding
/// them into `true`.
pub fn needs_renewal_checked(pem: &str, threshold_days: u32) -> Result<bool, DnsError> {
    needs_renewal_at_checked(pem, threshold_days, now_unix()?)
}

/// Lenient variant of [`needs_renewal_at_checked`]: unparseable PEM yields
/// `true`. See [`needs_renewal`] for the rationale.
pub fn needs_renewal_at(pem: &str, threshold_days: u32, now_unix: i64) -> bool {
    needs_renewal_at_checked(pem, threshold_days, now_unix).unwrap_or(true)
}

/// Same as [`needs_renewal_checked`], but with an explicit `now` (Unix
/// seconds) for deterministic testing.
pub fn needs_renewal_at_checked(
    pem: &str,
    threshold_days: u32,
    now_unix: i64,
) -> Result<bool, DnsError> {
    let leaf_der = parse_leaf_der(pem)?;
    let (_, cert): (_, X509Certificate) = X509Certificate::from_der(&leaf_der)
        .map_err(|e| DnsError::CertParse(format!("parse leaf certificate: {e}")))?;

    let not_after = cert.validity().not_after.timestamp();
    let threshold_seconds = i64::from(threshold_days) * 86_400;
    Ok(not_after - now_unix <= threshold_seconds)
}

/// Identity and validity metadata of a leaf certificate.
///
/// Timestamps are Unix seconds. `total_days` is the full lifetime
/// (`not_after - not_before`); `remaining_days` is measured from a given `now`
/// and may be negative for an expired cert. Both are truncated toward zero — a
/// cert with 29.9 days left reports `29`.
///
/// `subject_cn` and `sans` describe what the certificate is for: the subject
/// Common Name (if present) and the DNS names from the Subject Alternative Name
/// extension. `sans` carries only `dNSName` entries; other GeneralName kinds
/// (IP, email, URI) are ignored, since callers listing TLS certs want hostnames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertLifetime {
    /// `notBefore` as Unix seconds.
    pub not_before: i64,
    /// `notAfter` as Unix seconds.
    pub not_after: i64,
    /// Full lifetime in whole days (`not_after - not_before`). Never negative
    /// for a well-formed cert; clamped to `0` if the dates are inverted.
    pub total_days: i64,
    /// Whole days from `now` until `not_after`. Negative once expired.
    pub remaining_days: i64,
    /// Subject Common Name, if the subject carries one.
    pub subject_cn: Option<String>,
    /// DNS names from the Subject Alternative Name extension, in certificate
    /// order. Empty if the cert has no SAN extension or no `dNSName` entries.
    pub sans: Vec<String>,
}

/// Parse the leaf certificate in `pem` and report its identity and validity
/// relative to `now_unix`. Mirrors [`needs_renewal_at_checked`]'s parsing (leaf
/// only, unparseable PEM is an error). Use this to surface certificate metadata
/// — e.g. an API that lists certificates with their names and remaining lifetime.
pub fn cert_lifetime_at(pem: &str, now_unix: i64) -> Result<CertLifetime, DnsError> {
    let leaf_der = parse_leaf_der(pem)?;
    let (_, cert): (_, X509Certificate) = X509Certificate::from_der(&leaf_der)
        .map_err(|e| DnsError::CertParse(format!("parse leaf certificate: {e}")))?;

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned);

    let sans = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(name) => Some((*name).to_owned()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    Ok(CertLifetime {
        not_before,
        not_after,
        total_days: (not_after - not_before).max(0) / 86_400,
        remaining_days: (not_after - now_unix) / 86_400,
        subject_cn,
        sans,
    })
}

/// Same as [`cert_lifetime_at`] but uses the current system time.
pub fn cert_lifetime(pem: &str) -> Result<CertLifetime, DnsError> {
    cert_lifetime_at(pem, now_unix()?)
}

/// Decide renewal by *lifetime ratio* rather than a fixed window: renew once the
/// remaining lifetime drops below one third of the certificate's total lifetime,
/// but never sooner than `floor_days` before expiry.
///
/// The fixed-threshold [`needs_renewal_at_checked`] misfires on short-lived
/// certificates: a 7-day cert is "within 30 days of expiry" the moment it is
/// issued, so it would renew on every poll. Scaling the trigger to the cert's
/// own lifetime fixes that while staying friendly to long-lived certs via the
/// floor:
///
/// | lifetime | `total/3` | `floor_days = 30` | trigger |
/// |----------|-----------|-------------------|---------|
/// | 7 days   | ~2.3 d    | 30 d              | ~2 days left |
/// | 45 days  | 15 d      | 30 d              | 15 days left |
/// | 90 days  | 30 d      | 30 d              | 30 days left (unchanged) |
/// | 1 year   | ~121 d    | 30 d              | 30 days left (floor caps it) |
///
/// The 90-day case matches the legacy 30-day behaviour exactly, so swapping a
/// caller from the fixed API to this one is a no-op for Let's Encrypt's classic
/// profile. Pass `floor_days = 0` for a pure ratio with no cap.
///
/// An already-expired cert always renews. Unparseable PEM is an error here; use
/// [`needs_renewal_ratio_at`] for the lenient "garbage in → renew" variant.
pub fn needs_renewal_ratio_at_checked(
    pem: &str,
    floor_days: u32,
    now_unix: i64,
) -> Result<bool, DnsError> {
    let life = cert_lifetime_at(pem, now_unix)?;
    let remaining_seconds = life.not_after - now_unix;
    if remaining_seconds <= 0 {
        return Ok(true);
    }
    let ratio_seconds = (life.not_after - life.not_before).max(0) / 3;
    let floor_seconds = i64::from(floor_days) * 86_400;
    // Cap the ratio trigger so a long-lived cert isn't renewed months early:
    // `floor_days = 0` disables the cap and yields a pure ratio.
    let threshold_seconds = if floor_seconds == 0 {
        ratio_seconds
    } else {
        ratio_seconds.min(floor_seconds)
    };
    Ok(remaining_seconds <= threshold_seconds)
}

/// Same as [`needs_renewal_ratio_at_checked`] but uses the current system time.
pub fn needs_renewal_ratio_checked(pem: &str, floor_days: u32) -> Result<bool, DnsError> {
    needs_renewal_ratio_at_checked(pem, floor_days, now_unix()?)
}

/// Lenient variant of [`needs_renewal_ratio_at_checked`]: unparseable PEM yields
/// `true`. See [`needs_renewal`] for the rationale.
pub fn needs_renewal_ratio_at(pem: &str, floor_days: u32, now_unix: i64) -> bool {
    needs_renewal_ratio_at_checked(pem, floor_days, now_unix).unwrap_or(true)
}

/// Lenient, system-time variant of [`needs_renewal_ratio_at_checked`].
pub fn needs_renewal_ratio(pem: &str, floor_days: u32) -> bool {
    needs_renewal_ratio_checked(pem, floor_days).unwrap_or(true)
}

/// Current time as Unix seconds, surfaced as a [`DnsError`] if the clock is set
/// before the epoch.
fn now_unix() -> Result<i64, DnsError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| DnsError::CertParse(format!("system time before epoch: {e}")))?
        .as_secs() as i64)
}

fn parse_leaf_der(pem: &str) -> Result<Vec<u8>, DnsError> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    match Pem::read(&mut cursor) {
        Ok((pem, _consumed)) => {
            if pem.label != "CERTIFICATE" {
                return Err(DnsError::CertParse(format!(
                    "expected CERTIFICATE PEM, got {}",
                    pem.label
                )));
            }
            Ok(pem.contents)
        }
        Err(e) => Err(DnsError::CertParse(format!("no PEM block found: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use time::OffsetDateTime;

    /// Generate a self-signed certificate whose validity ends at `not_after_unix`.
    fn cert_pem_expiring_at(not_after_unix: i64) -> String {
        cert_pem_with_lifetime(not_after_unix, 365)
    }

    /// Like [`cert_pem_expiring_at`] but with an explicit total lifetime in days,
    /// so tests can exercise short-lived (7d/45d) and classic (90d) profiles.
    fn cert_pem_with_lifetime(not_after_unix: i64, lifetime_days: i64) -> String {
        let not_after = OffsetDateTime::from_unix_timestamp(not_after_unix).unwrap();
        let not_before = not_after - time::Duration::days(lifetime_days);

        let mut params = CertificateParams::new(vec!["test.example".to_string()]).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;

        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.pem()
    }

    /// Self-signed cert with an explicit subject Common Name and a set of SAN
    /// DNS names, for exercising the identity fields of [`CertLifetime`].
    fn cert_pem_with_identity(cn: &str, sans: &[&str]) -> String {
        use rcgen::{DnType, SanType};

        let mut params =
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        // `new()` populates SANs from the names above; set them explicitly so the
        // ordering and content are unambiguous for the assertion.
        params.subject_alt_names = sans
            .iter()
            .map(|s| SanType::DnsName(s.to_string().try_into().unwrap()))
            .collect();

        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.pem()
    }

    #[test]
    fn returns_false_when_far_from_expiry() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_expiring_at(not_after);
        let now = not_after - 60 * 86_400; // 60 days before expiry
        assert!(!needs_renewal_at_checked(&pem, 30, now).unwrap());
        assert!(!needs_renewal_at(&pem, 30, now));
    }

    #[test]
    fn returns_true_when_within_threshold() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_expiring_at(not_after);
        let now = not_after - 10 * 86_400; // 10 days before expiry
        assert!(needs_renewal_at_checked(&pem, 30, now).unwrap());
        assert!(needs_renewal_at(&pem, 30, now));
    }

    #[test]
    fn returns_true_when_already_expired() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_expiring_at(not_after);
        let now = not_after + 86_400; // 1 day after expiry
        assert!(needs_renewal_at_checked(&pem, 30, now).unwrap());
    }

    #[test]
    fn checked_variant_rejects_non_pem_input() {
        let err = needs_renewal_at_checked("not a certificate", 30, 0).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("pem"));
    }

    #[test]
    fn lenient_variant_treats_unparseable_as_needs_renewal() {
        // The whole point of the bool API: garbage in → "renew it" rather
        // than a panic or a silent false.
        assert!(needs_renewal_at("not a certificate", 30, 0));
        assert!(needs_renewal("not a certificate", 30));
    }

    #[test]
    fn parses_only_leaf_when_chain_present() {
        let not_after = 1_900_000_000;
        let leaf = cert_pem_expiring_at(not_after);
        // The function should read the first cert; appending a second cert
        // (which would have different dates) shouldn't change the answer.
        let chain = format!("{leaf}{}", cert_pem_expiring_at(not_after - 365 * 86_400));
        let now = not_after - 60 * 86_400;
        assert!(!needs_renewal_at_checked(&chain, 30, now).unwrap());
    }

    const DAY: i64 = 86_400;

    #[test]
    fn cert_lifetime_reports_window_and_day_counts() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_with_lifetime(not_after, 90);
        let now = not_after - 10 * DAY;
        let life = cert_lifetime_at(&pem, now).unwrap();

        assert_eq!(life.not_after, not_after);
        assert_eq!(life.not_before, not_after - 90 * DAY);
        assert_eq!(life.total_days, 90);
        assert_eq!(life.remaining_days, 10);
    }

    #[test]
    fn cert_lifetime_reports_subject_cn_and_sans() {
        let pem =
            cert_pem_with_identity("shop.example.com", &["shop.example.com", "www.example.com"]);
        let life = cert_lifetime(&pem).unwrap();

        assert_eq!(life.subject_cn.as_deref(), Some("shop.example.com"));
        assert_eq!(life.sans, vec!["shop.example.com", "www.example.com"]);
    }

    #[test]
    fn cert_lifetime_sans_empty_when_no_san_extension() {
        // A cert with only a subject CN and no SAN names: `sans` is empty,
        // `subject_cn` is still populated.
        let pem = cert_pem_with_identity("legacy.example.com", &[]);
        let life = cert_lifetime(&pem).unwrap();

        assert_eq!(life.subject_cn.as_deref(), Some("legacy.example.com"));
        assert!(life.sans.is_empty());
    }

    #[test]
    fn cert_lifetime_remaining_goes_negative_when_expired() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_with_lifetime(not_after, 90);
        let now = not_after + 3 * DAY;
        assert_eq!(cert_lifetime_at(&pem, now).unwrap().remaining_days, -3);
    }

    #[test]
    fn cert_lifetime_rejects_non_pem() {
        assert!(cert_lifetime_at("not a cert", 0).is_err());
    }

    /// The 90-day / 30-day-floor case must behave exactly like the legacy
    /// fixed-threshold API: renewal fires at the 30-days-left mark, not before.
    #[test]
    fn ratio_matches_legacy_for_ninety_day_certs() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_with_lifetime(not_after, 90);

        // 31 days left: not yet (ratio threshold is 30 days).
        let now = not_after - 31 * DAY;
        assert!(!needs_renewal_ratio_at_checked(&pem, 30, now).unwrap());
        assert!(!needs_renewal_at_checked(&pem, 30, now).unwrap());

        // 30 days left: both APIs trigger.
        let now = not_after - 30 * DAY;
        assert!(needs_renewal_ratio_at_checked(&pem, 30, now).unwrap());
        assert!(needs_renewal_at_checked(&pem, 30, now).unwrap());
    }

    /// A 7-day cert must NOT be considered "needs renewal" the moment it is
    /// issued — that was the fixed-threshold bug. Ratio trigger is ~2.3 days.
    #[test]
    fn ratio_does_not_renew_fresh_short_lived_cert() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_with_lifetime(not_after, 7);

        // Fresh (6 days left): fixed-30 would renew, ratio must not.
        let now = not_after - 6 * DAY;
        assert!(needs_renewal_at_checked(&pem, 30, now).unwrap());
        assert!(!needs_renewal_ratio_at_checked(&pem, 30, now).unwrap());

        // 2 days left (< 7/3 ≈ 2.33): now it renews.
        let now = not_after - 2 * DAY;
        assert!(needs_renewal_ratio_at_checked(&pem, 30, now).unwrap());
    }

    #[test]
    fn ratio_triggers_at_one_third_for_forty_five_day_cert() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_with_lifetime(not_after, 45); // 45/3 = 15 days

        let now = not_after - 16 * DAY;
        assert!(!needs_renewal_ratio_at_checked(&pem, 30, now).unwrap());
        let now = not_after - 15 * DAY;
        assert!(needs_renewal_ratio_at_checked(&pem, 30, now).unwrap());
    }

    /// The floor caps the ratio so a long-lived cert isn't renewed months early.
    #[test]
    fn ratio_floor_caps_long_lived_certs() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_with_lifetime(not_after, 365); // ratio alone = ~121 days

        // 90 days left: pure ratio (floor 0) would renew, floored-30 must not.
        let now = not_after - 90 * DAY;
        assert!(needs_renewal_ratio_at_checked(&pem, 0, now).unwrap());
        assert!(!needs_renewal_ratio_at_checked(&pem, 30, now).unwrap());

        // 29 days left: floor kicks in.
        let now = not_after - 29 * DAY;
        assert!(needs_renewal_ratio_at_checked(&pem, 30, now).unwrap());
    }

    #[test]
    fn ratio_renews_expired_cert() {
        let not_after = 1_900_000_000;
        let pem = cert_pem_with_lifetime(not_after, 90);
        let now = not_after + DAY;
        assert!(needs_renewal_ratio_at_checked(&pem, 30, now).unwrap());
    }

    #[test]
    fn ratio_lenient_treats_unparseable_as_needs_renewal() {
        assert!(needs_renewal_ratio_at("not a cert", 30, 0));
        assert!(needs_renewal_ratio("not a cert", 30));
    }
}

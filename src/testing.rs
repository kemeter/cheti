//! In-memory test doubles, gated behind the `testing` feature.
//!
//! Downstream crates that wire up DNS-01 (e.g. a reverse proxy delegating to
//! [`crate::Dns01Solver`]) can use [`MockDnsProvider`] to integration-test
//! their plumbing without talking to a real DNS API.
//!
//! Because the solver still runs live propagation polling by default, pair the
//! mock with `skip_propagation_check` so no real resolver is queried:
//!
//! ```no_run
//! use std::time::Duration;
//! use cheti::Dns01Solver;
//! use cheti::testing::MockDnsProvider;
//!
//! let provider = MockDnsProvider::new();
//! let solver = Dns01Solver::new(provider).skip_propagation_check(Duration::ZERO);
//! // drive `solver.solve_and_finalize(order)` against a test ACME server...
//! ```

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::error::DnsError;
use crate::provider::{DnsProvider, PropagationTiming};
use crate::tls_alpn::ChallengeResponder;

/// A `DnsProvider` that records `present`/`cleanup` calls in memory instead
/// of touching a real DNS zone. Clone-able; clones share the same record log.
#[derive(Clone, Default)]
pub struct MockDnsProvider {
    records: Arc<Mutex<Vec<(String, String)>>>,
    fail_present: bool,
}

impl MockDnsProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every `present` call return an error, to exercise failure paths.
    pub fn failing() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
            fail_present: true,
        }
    }

    /// All `(fqdn, value)` pairs currently "present" in the mock zone.
    /// Cleaned-up records are removed.
    pub fn present_records(&self) -> Vec<(String, String)> {
        self.records.lock().expect("mock lock poisoned").clone()
    }

    /// True if the given TXT value is currently present for `fqdn`.
    pub fn has_record(&self, fqdn: &str, value: &str) -> bool {
        self.records
            .lock()
            .expect("mock lock poisoned")
            .iter()
            .any(|(f, v)| f == fqdn && v == value)
    }
}

#[async_trait]
impl DnsProvider for MockDnsProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        if self.fail_present {
            return Err(DnsError::Api(format!("mock present failure for {fqdn}")));
        }
        self.records
            .lock()
            .expect("mock lock poisoned")
            .push((fqdn.to_string(), value.to_string()));
        Ok(())
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        self.records
            .lock()
            .expect("mock lock poisoned")
            .retain(|(f, v)| !(f == fqdn && v == value));
        Ok(())
    }

    fn timing(&self) -> PropagationTiming {
        // Tight timing; callers should still use skip_propagation_check to
        // avoid real resolver queries entirely.
        PropagationTiming {
            timeout: std::time::Duration::from_secs(1),
            interval: std::time::Duration::from_millis(10),
        }
    }
}

/// A [`ChallengeResponder`] that records `present`/`cleanup` calls in memory
/// instead of serving TLS. Clone-able; clones share the same log. Lets a
/// downstream crate integration-test its TLS-ALPN-01 wiring without standing up
/// a real TLS responder.
/// One recorded presentation: `(domain, cert_der, key_der)`.
type Presentation = (String, Vec<u8>, Vec<u8>);

#[derive(Clone, Default)]
pub struct MockChallengeResponder {
    presented: Arc<Mutex<Vec<Presentation>>>,
    fail_present: bool,
}

impl MockChallengeResponder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every `present` call return an error, to exercise failure paths.
    pub fn failing() -> Self {
        Self {
            presented: Arc::new(Mutex::new(Vec::new())),
            fail_present: true,
        }
    }

    /// Domains with a challenge certificate currently presented.
    pub fn presented_domains(&self) -> Vec<String> {
        self.presented
            .lock()
            .expect("mock lock poisoned")
            .iter()
            .map(|(d, _, _)| d.clone())
            .collect()
    }

    /// True if a challenge certificate is currently presented for `domain`.
    pub fn is_presenting(&self, domain: &str) -> bool {
        self.presented
            .lock()
            .expect("mock lock poisoned")
            .iter()
            .any(|(d, _, _)| d == domain)
    }
}

#[async_trait]
impl ChallengeResponder for MockChallengeResponder {
    async fn present(
        &self,
        domain: &str,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<(), DnsError> {
        if self.fail_present {
            return Err(DnsError::Other(format!(
                "mock present failure for {domain}"
            )));
        }
        self.presented.lock().expect("mock lock poisoned").push((
            domain.to_string(),
            cert_der,
            key_der,
        ));
        Ok(())
    }

    async fn cleanup(&self, domain: &str) -> Result<(), DnsError> {
        self.presented
            .lock()
            .expect("mock lock poisoned")
            .retain(|(d, _, _)| d != domain);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn present_then_cleanup_round_trips() {
        let mock = MockDnsProvider::new();
        mock.present("_acme-challenge.example.com", "abc")
            .await
            .unwrap();
        assert!(mock.has_record("_acme-challenge.example.com", "abc"));

        mock.cleanup("_acme-challenge.example.com", "abc")
            .await
            .unwrap();
        assert!(!mock.has_record("_acme-challenge.example.com", "abc"));
        assert!(mock.present_records().is_empty());
    }

    #[tokio::test]
    async fn failing_mock_errors_on_present() {
        let mock = MockDnsProvider::failing();
        let err = mock.present("x", "y").await.unwrap_err();
        assert!(err.to_string().contains("mock present failure"));
    }

    #[tokio::test]
    async fn clones_share_record_log() {
        let mock = MockDnsProvider::new();
        let clone = mock.clone();
        mock.present("a", "1").await.unwrap();
        assert!(clone.has_record("a", "1"));
    }

    #[tokio::test]
    async fn challenge_responder_present_then_cleanup_round_trips() {
        let mock = MockChallengeResponder::new();
        mock.present("example.com", vec![1, 2, 3], vec![4, 5, 6])
            .await
            .unwrap();
        assert!(mock.is_presenting("example.com"));

        mock.cleanup("example.com").await.unwrap();
        assert!(!mock.is_presenting("example.com"));
        assert!(mock.presented_domains().is_empty());
    }

    #[tokio::test]
    async fn failing_challenge_responder_errors_on_present() {
        let mock = MockChallengeResponder::failing();
        let err = mock.present("x", vec![], vec![]).await.unwrap_err();
        assert!(err.to_string().contains("mock present failure"));
    }
}

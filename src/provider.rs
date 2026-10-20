use std::time::Duration;

use async_trait::async_trait;

use crate::error::DnsError;

/// How long, and how often, the solver polls DNS for a placed record.
#[derive(Debug, Clone, Copy)]
pub struct PropagationTiming {
    /// Give up after this long. Defaults to 120s.
    pub timeout: Duration,
    /// Wait this long between two polls. Defaults to 5s.
    pub interval: Duration,
}

impl Default for PropagationTiming {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            interval: Duration::from_secs(5),
        }
    }
}

/// A DNS provider that can place and remove the TXT records required by an
/// ACME DNS-01 challenge.
///
/// This trait is object-safe (via [`async_trait`](macro@async_trait)), so it can be used as
/// `Box<dyn DnsProvider>` when the concrete provider is chosen at runtime.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Adds `value` to the TXT records at `fqdn`.
    ///
    /// Must keep any other value already there: a wildcard and its apex share
    /// the same `_acme-challenge` name and are validated at the same time.
    /// Presenting a value that is already there must succeed.
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError>;

    /// Removes `value` from the TXT records at `fqdn`, leaving any other value
    /// in place. Removing a value that is not there must succeed.
    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError>;

    /// Propagation polling suited to this provider. Defaults to
    /// [`PropagationTiming::default`].
    fn timing(&self) -> PropagationTiming {
        PropagationTiming::default()
    }
}

/// Forwarding impl so `Box<dyn DnsProvider>` itself implements `DnsProvider`,
/// letting it be passed to `Dns01Solver::new` like any concrete provider.
#[async_trait]
impl DnsProvider for Box<dyn DnsProvider> {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        (**self).present(fqdn, value).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        (**self).cleanup(fqdn, value).await
    }

    fn timing(&self) -> PropagationTiming {
        (**self).timing()
    }
}

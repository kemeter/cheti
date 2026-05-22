use std::time::Duration;

use async_trait::async_trait;

use crate::error::DnsError;

#[derive(Debug, Clone, Copy)]
pub struct PropagationTiming {
    pub timeout: Duration,
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
/// This trait is object-safe (via [`async_trait`]), so it can be used as
/// `Box<dyn DnsProvider>` when the concrete provider is chosen at runtime.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError>;

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError>;

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

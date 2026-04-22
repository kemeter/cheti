use std::future::Future;
use std::time::Duration;

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

pub trait DnsProvider: Send + Sync {
    fn present(&self, fqdn: &str, value: &str)
        -> impl Future<Output = Result<(), DnsError>> + Send;

    fn cleanup(&self, fqdn: &str, value: &str)
        -> impl Future<Output = Result<(), DnsError>> + Send;

    fn timing(&self) -> PropagationTiming {
        PropagationTiming::default()
    }
}

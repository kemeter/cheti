use std::net::SocketAddr;
use std::time::Instant;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use crate::error::DnsError;
use crate::provider::PropagationTiming;

pub const DEFAULT_RESOLVERS: &[&str] = &["1.1.1.1:53", "8.8.8.8:53"];

/// Poll the given resolvers until a TXT record at `fqdn` contains `expected`,
/// or the timeout expires.
///
/// Returns `Ok(())` as soon as any resolver returns a TXT containing the
/// expected value. Otherwise, returns `DnsError::PropagationTimeout`.
pub async fn wait_for_propagation(
    fqdn: &str,
    expected: &str,
    resolvers: &[&str],
    timing: PropagationTiming,
) -> Result<(), DnsError> {
    let addrs = parse_resolvers(resolvers)?;
    let resolver = build_resolver(&addrs);

    let start = Instant::now();
    let fqdn_trimmed = fqdn.trim_end_matches('.');

    loop {
        if let Ok(response) = resolver.txt_lookup(fqdn_trimmed).await {
            let found = response.iter().any(|record| {
                record
                    .iter()
                    .any(|data| std::str::from_utf8(data).is_ok_and(|s| s == expected))
            });
            if found {
                return Ok(());
            }
        }

        if start.elapsed() >= timing.timeout {
            return Err(DnsError::PropagationTimeout {
                fqdn: fqdn.to_string(),
                timeout_secs: timing.timeout.as_secs(),
            });
        }

        tokio::time::sleep(timing.interval).await;
    }
}

fn parse_resolvers(resolvers: &[&str]) -> Result<Vec<SocketAddr>, DnsError> {
    resolvers
        .iter()
        .map(|addr| {
            addr.parse::<SocketAddr>()
                .map_err(|e| DnsError::Resolver(format!("invalid resolver address {addr}: {e}")))
        })
        .collect()
}

fn build_resolver(addrs: &[SocketAddr]) -> TokioAsyncResolver {
    let group = NameServerConfigGroup::from_ips_clear(
        &addrs.iter().map(|a| a.ip()).collect::<Vec<_>>(),
        addrs.first().map(|a| a.port()).unwrap_or(53),
        true,
    );
    let config = ResolverConfig::from_parts(None, vec![], group);
    TokioAsyncResolver::tokio(config, ResolverOpts::default())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn timeout_fires_when_record_absent() {
        let timing = PropagationTiming {
            timeout: Duration::from_millis(50),
            interval: Duration::from_millis(10),
        };
        let result = wait_for_propagation(
            "nonexistent.invalid.example.",
            "anything",
            DEFAULT_RESOLVERS,
            timing,
        )
        .await;
        assert!(matches!(result, Err(DnsError::PropagationTimeout { .. })));
    }

    #[test]
    fn invalid_resolver_is_reported() {
        let err = parse_resolvers(&["not-an-address"]).unwrap_err();
        assert!(matches!(err, DnsError::Resolver(_)));
    }
}

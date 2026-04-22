use std::net::SocketAddr;
use std::time::Instant;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use crate::dns::zone::find_zone;
use crate::error::DnsError;
use crate::provider::PropagationTiming;

/// Fallback public resolvers used when authoritative NS lookup fails.
///
/// These are used on best-effort basis. Public resolvers see cached data and
/// cannot guarantee that the TXT record is visible on all authoritative NS.
pub const DEFAULT_RESOLVERS: &[&str] = &["1.1.1.1:53", "8.8.8.8:53"];

/// Poll DNS until a TXT record at `fqdn` contains `expected`, or the timeout expires.
///
/// Queries the authoritative nameservers of the zone by default (more reliable
/// than public resolvers, since Let's Encrypt itself queries authoritative NS).
/// Falls back to `fallback_resolvers` if authoritative NS lookup fails.
///
/// Returns `Ok(())` as soon as any queried NS returns a TXT containing `expected`.
pub async fn wait_for_propagation(
    fqdn: &str,
    expected: &str,
    fallback_resolvers: &[&str],
    timing: PropagationTiming,
) -> Result<(), DnsError> {
    let fqdn_trimmed = fqdn.trim_end_matches('.');

    let authoritative = authoritative_resolver(fqdn_trimmed).await.ok();
    let fallback = build_resolver(&parse_resolvers(fallback_resolvers)?);

    let start = Instant::now();
    loop {
        let resolver = authoritative.as_ref().unwrap_or(&fallback);

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

/// Resolve the authoritative NS for the zone hosting `fqdn`, then build a
/// resolver that queries those NS directly.
async fn authoritative_resolver(fqdn: &str) -> Result<TokioAsyncResolver, DnsError> {
    let zone = find_zone(fqdn).await?;
    let default = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let ns_response = default
        .ns_lookup(&zone)
        .await
        .map_err(|e| DnsError::Resolver(format!("NS lookup for {zone}: {e}")))?;

    let mut ns_ips = Vec::new();
    for ns in ns_response.iter() {
        let ns_name = ns.0.to_string();
        if let Ok(lookup) = default.lookup_ip(&ns_name).await {
            for ip in lookup.iter() {
                ns_ips.push(SocketAddr::new(ip, 53));
            }
        }
    }

    if ns_ips.is_empty() {
        return Err(DnsError::Resolver(format!(
            "no authoritative NS found for zone {zone}"
        )));
    }

    Ok(build_resolver(&ns_ips))
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
    use super::*;

    #[test]
    fn invalid_resolver_is_reported() {
        let err = parse_resolvers(&["not-an-address"]).unwrap_err();
        assert!(matches!(err, DnsError::Resolver(_)));
    }
}

use std::net::SocketAddr;
use std::time::Instant;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

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
    let fallback = build_resolver(&parse_resolvers(fallback_resolvers)?)?;

    let start = Instant::now();
    loop {
        let resolver = authoritative.as_ref().unwrap_or(&fallback);

        if let Ok(response) = resolver.lookup(fqdn_trimmed, RecordType::TXT).await {
            let found = response.answers().iter().any(|record| {
                matches!(&record.data, RData::TXT(txt)
                if txt.txt_data.iter().any(|data| {
                    std::str::from_utf8(data).is_ok_and(|s| s == expected)
                }))
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
async fn authoritative_resolver(fqdn: &str) -> Result<TokioResolver, DnsError> {
    let zone = find_zone(fqdn).await?;
    let default = TokioResolver::builder_tokio()
        .map_err(|e| DnsError::Resolver(format!("system resolver init: {e}")))?
        .build()
        .map_err(|e| DnsError::Resolver(format!("system resolver build: {e}")))?;

    let ns_response = default
        .lookup(&zone, RecordType::NS)
        .await
        .map_err(|e| DnsError::Resolver(format!("NS lookup for {zone}: {e}")))?;

    let mut ns_ips = Vec::new();
    for record in ns_response.answers() {
        let RData::NS(ns) = &record.data else {
            continue;
        };
        let ns_name = ns.to_string();
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

    build_resolver(&ns_ips)
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

fn build_resolver(addrs: &[SocketAddr]) -> Result<TokioResolver, DnsError> {
    let name_servers = addrs
        .iter()
        .map(|addr| {
            let connections = vec![connection_on_port(ConnectionConfig::udp(), addr.port())];
            NameServerConfig::new(addr.ip(), true, connections)
        })
        .collect();

    let config = ResolverConfig::from_parts(None, vec![], name_servers);
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| DnsError::Resolver(format!("resolver build: {e}")))
}

fn connection_on_port(mut conn: ConnectionConfig, port: u16) -> ConnectionConfig {
    conn.port = port;
    conn
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

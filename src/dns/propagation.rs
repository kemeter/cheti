use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use tokio::time::Instant;

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
/// than public resolvers, since Let's Encrypt itself queries authoritative NS)
/// and returns `Ok(())` once **every** one of them serves `expected`: the CA
/// validates from several vantage points, so a lagging secondary would fail
/// the challenge. A nameserver counts as confirmed as soon as any of its
/// addresses answers, so an unreachable IPv6 address does not hold it back.
///
/// Falls back to `fallback_resolvers` if the authoritative NS cannot be
/// found, and then returns as soon as any of them sees `expected`.
pub async fn wait_for_propagation(
    fqdn: &str,
    expected: &str,
    fallback_resolvers: &[&str],
    timing: PropagationTiming,
) -> Result<(), DnsError> {
    let fqdn_trimmed = fqdn.trim_end_matches('.');

    let targets = match authoritative_nameservers(fqdn_trimmed).await {
        Ok(nameservers) => nameservers,
        Err(_) => vec![build_resolver(&parse_resolvers(fallback_resolvers)?)?],
    };

    poll_until_all_confirm(targets, fqdn, timing, |resolver| {
        // A cheap handle clone, so the query future does not borrow the list.
        let resolver = resolver.clone();
        async move { serves_value(&resolver, fqdn_trimmed, expected).await }
    })
    .await
}

/// Polls every target until each one has confirmed once, re-querying only
/// the targets not confirmed yet.
async fn poll_until_all_confirm<T, F, Fut>(
    targets: Vec<T>,
    fqdn: &str,
    timing: PropagationTiming,
    check: F,
) -> Result<(), DnsError>
where
    F: Fn(&T) -> Fut,
    Fut: Future<Output = bool>,
{
    let mut pending = targets;
    let start = Instant::now();
    loop {
        let mut still_pending = Vec::with_capacity(pending.len());
        for target in pending {
            if !check(&target).await {
                still_pending.push(target);
            }
        }
        pending = still_pending;
        if pending.is_empty() {
            return Ok(());
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

async fn serves_value(resolver: &TokioResolver, fqdn: &str, expected: &str) -> bool {
    let Ok(response) = resolver.lookup(fqdn, RecordType::TXT).await else {
        return false;
    };
    response.answers().iter().any(|record| {
        matches!(&record.data, RData::TXT(txt)
        if txt.txt_data.iter().any(|data| {
            std::str::from_utf8(data).is_ok_and(|s| s == expected)
        }))
    })
}

/// Resolve the authoritative NS for the zone hosting `fqdn`, and build one
/// resolver per nameserver, querying all of its addresses directly. A
/// nameserver whose name does not resolve is skipped.
async fn authoritative_nameservers(fqdn: &str) -> Result<Vec<TokioResolver>, DnsError> {
    let zone = find_zone(fqdn).await?;
    let default = TokioResolver::builder_tokio()
        .map_err(|e| DnsError::Resolver(format!("system resolver init: {e}")))?
        .build()
        .map_err(|e| DnsError::Resolver(format!("system resolver build: {e}")))?;

    let ns_response = default
        .lookup(&zone, RecordType::NS)
        .await
        .map_err(|e| DnsError::Resolver(format!("NS lookup for {zone}: {e}")))?;

    let mut names: Vec<String> = ns_response
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::NS(ns) => Some(ns.to_string().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    names.sort();
    names.dedup();

    let mut nameservers = Vec::new();
    for name in names {
        let Ok(lookup) = default.lookup_ip(&name).await else {
            continue;
        };
        let addrs: Vec<SocketAddr> = lookup.iter().map(|ip| SocketAddr::new(ip, 53)).collect();
        if !addrs.is_empty() {
            nameservers.push(build_resolver(&addrs)?);
        }
    }

    if nameservers.is_empty() {
        return Err(DnsError::Resolver(format!(
            "no authoritative NS found for zone {zone}"
        )));
    }
    Ok(nameservers)
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
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    // Each poll must reach the servers: a cached answer, negative ones above
    // all, would hide a record that has appeared since.
    let options = builder.options_mut();
    options.positive_max_ttl = Some(Duration::ZERO);
    options.negative_max_ttl = Some(Duration::ZERO);
    builder
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

    use std::cell::RefCell;
    use std::collections::HashMap;

    fn timing(timeout_secs: u64) -> PropagationTiming {
        PropagationTiming {
            timeout: Duration::from_secs(timeout_secs),
            interval: Duration::from_secs(1),
        }
    }

    /// `ready_after[name]` is the number of failed checks before `name`
    /// confirms (`None`: never). Returns the per-target check counts.
    async fn run(
        ready_after: &[(&'static str, Option<usize>)],
        timeout_secs: u64,
    ) -> (Result<(), DnsError>, HashMap<&'static str, usize>) {
        let calls: RefCell<HashMap<&'static str, usize>> = RefCell::new(HashMap::new());
        let targets: Vec<(&'static str, Option<usize>)> = ready_after.to_vec();
        let result = poll_until_all_confirm(
            targets,
            "_acme-challenge.example.com",
            timing(timeout_secs),
            |(name, after)| {
                let mut calls = calls.borrow_mut();
                let count = calls.entry(*name).or_default();
                *count += 1;
                let ready = after.is_some_and(|n| *count > n);
                async move { ready }
            },
        )
        .await;
        (result, calls.into_inner())
    }

    #[tokio::test(start_paused = true)]
    async fn waits_for_every_nameserver() {
        let (result, calls) = run(&[("ns1", Some(0)), ("ns2", Some(2))], 60).await;
        assert!(result.is_ok());
        // ns1 confirmed on the first poll and was not asked again.
        assert_eq!(calls["ns1"], 1);
        assert_eq!(calls["ns2"], 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lagging_nameserver_times_out() {
        let (result, calls) = run(&[("ns1", Some(0)), ("ns2", None)], 5).await;
        assert!(matches!(
            result,
            Err(DnsError::PropagationTimeout {
                timeout_secs: 5,
                ..
            })
        ));
        assert_eq!(calls["ns1"], 1);
        assert!(calls["ns2"] > 1);
    }

    #[test]
    fn invalid_resolver_is_reported() {
        let err = parse_resolvers(&["not-an-address"]).unwrap_err();
        assert!(matches!(err, DnsError::Resolver(_)));
    }
}

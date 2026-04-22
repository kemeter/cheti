use std::sync::OnceLock;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use crate::error::DnsError;

fn shared_resolver() -> &'static TokioAsyncResolver {
    static RESOLVER: OnceLock<TokioAsyncResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
    })
}

/// Resolve the authoritative zone for a FQDN by walking up labels until a SOA
/// record is found.
///
/// For `api.v2.kemeter.app`, this returns `kemeter.app` if that is the closest
/// ancestor with an SOA record.
///
/// Note: the SOA lookup goes through the default system resolvers. Results are
/// not DNSSEC-validated; treat this as a best-effort lookup.
pub async fn find_zone(fqdn: &str) -> Result<String, DnsError> {
    let resolver = shared_resolver();
    let trimmed = fqdn.trim_end_matches('.');
    let mut candidate = trimmed.to_string();

    loop {
        if candidate.is_empty() || !candidate.contains('.') {
            return Err(DnsError::ZoneNotFound(fqdn.to_string()));
        }

        if let Ok(response) = resolver.soa_lookup(&candidate).await {
            if response.iter().next().is_some() {
                return Ok(candidate);
            }
        }

        let Some((_, rest)) = candidate.split_once('.') else {
            return Err(DnsError::ZoneNotFound(fqdn.to_string()));
        };
        if rest.is_empty() || rest.starts_with('.') {
            return Err(DnsError::ZoneNotFound(fqdn.to_string()));
        }
        candidate = rest.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires internet"]
    async fn finds_zone_for_subdomain() {
        let zone = find_zone("api.kemeter.app").await.unwrap();
        assert_eq!(zone, "kemeter.app");
    }

    #[tokio::test]
    #[ignore = "requires internet"]
    async fn fails_on_nonexistent_domain() {
        let result = find_zone("does-not-exist.invalid.example").await;
        assert!(matches!(result, Err(DnsError::ZoneNotFound(_))));
    }
}

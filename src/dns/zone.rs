use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use crate::error::DnsError;

/// Resolve the authoritative zone for a FQDN by walking up labels until a SOA
/// record is found.
///
/// For `api.v2.kemeter.app`, this returns `kemeter.app` if that is the closest
/// ancestor with an SOA record.
pub async fn find_zone(fqdn: &str) -> Result<String, DnsError> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let trimmed = fqdn.trim_end_matches('.');
    let mut candidate = trimmed.to_string();

    loop {
        if let Ok(response) = resolver.soa_lookup(&candidate).await {
            if response.iter().next().is_some() {
                return Ok(candidate);
            }
        }

        match candidate.split_once('.') {
            Some((_, rest)) if !rest.is_empty() && rest.contains('.') => {
                candidate = rest.to_string();
            }
            _ => return Err(DnsError::ZoneNotFound(fqdn.to_string())),
        }
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

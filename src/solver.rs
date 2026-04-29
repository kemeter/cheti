use std::time::Duration;

use instant_acme::{
    AuthorizationStatus, ChallengeType, Identifier, Order, OrderStatus, RetryPolicy,
};

use crate::dns::wait_for_propagation;
use crate::error::DnsError;
use crate::provider::{DnsProvider, PropagationTiming};

/// Records placed by the solver during `solve_and_finalize`. Tracked so that
/// `cleanup` runs even when ACME validation fails partway through.
struct PlacedRecord {
    fqdn: String,
    value: String,
}

/// End-to-end DNS-01 orchestrator. Wraps a `DnsProvider` and drives an
/// `instant_acme::Order` from `Pending` to a usable certificate, calling
/// `present` / `cleanup` on the provider as needed.
pub struct Dns01Solver<P: DnsProvider> {
    provider: P,
    fallback_resolvers: Vec<String>,
    timing: Option<PropagationTiming>,
    skip_propagation: Option<Duration>,
}

impl<P: DnsProvider> Dns01Solver<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            fallback_resolvers: crate::dns::DEFAULT_RESOLVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            timing: None,
            skip_propagation: None,
        }
    }

    pub fn with_resolvers(mut self, resolvers: Vec<impl Into<String>>) -> Self {
        self.fallback_resolvers = resolvers.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timing
            .get_or_insert_with(PropagationTiming::default)
            .timeout = timeout;
        self
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.timing
            .get_or_insert_with(PropagationTiming::default)
            .interval = interval;
        self
    }

    /// Skip the propagation poll and sleep `delay` instead before telling ACME
    /// to validate. Use only when the active poll fails for unrelated reasons
    /// (split-horizon DNS, anycast lag), since it disables the safety net.
    pub fn skip_propagation_check(mut self, delay: Duration) -> Self {
        self.skip_propagation = Some(delay);
        self
    }

    /// Drive the order from Pending to a certificate. Returns
    /// `(certificate_chain_pem, private_key_pem)`. Cleanup of placed TXT
    /// records is best-effort and runs even on error paths.
    pub async fn solve_and_finalize(
        &self,
        mut order: Order,
    ) -> Result<(String, String), DnsError> {
        let placed = self.present_all(&mut order).await?;
        let outcome = self.finalize(&mut order).await;
        self.cleanup_all(&placed).await;
        outcome
    }

    async fn present_all(&self, order: &mut Order) -> Result<Vec<PlacedRecord>, DnsError> {
        let mut placed: Vec<PlacedRecord> = Vec::new();

        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = match result {
                Ok(a) => a,
                Err(e) => {
                    self.cleanup_all(&placed).await;
                    return Err(DnsError::Acme(e.to_string()));
                }
            };

            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => {
                    self.cleanup_all(&placed).await;
                    return Err(DnsError::ChallengeInvalid(format!("{other:?}")));
                }
            }

            let domain = match authz.identifier().identifier {
                Identifier::Dns(d) => d.clone(),
                other => {
                    self.cleanup_all(&placed).await;
                    return Err(DnsError::Other(format!(
                        "unsupported identifier type: {other:?}"
                    )));
                }
            };

            let mut challenge = match authz.challenge(ChallengeType::Dns01) {
                Some(c) => c,
                None => {
                    self.cleanup_all(&placed).await;
                    return Err(DnsError::NoDns01Challenge(domain));
                }
            };

            let dns_value = challenge.key_authorization().dns_value();
            let fqdn = format!("_acme-challenge.{domain}");

            if let Err(e) = self.provider.present(&fqdn, &dns_value).await {
                self.cleanup_all(&placed).await;
                return Err(e);
            }
            placed.push(PlacedRecord {
                fqdn: fqdn.clone(),
                value: dns_value.clone(),
            });

            if self.skip_propagation.is_none() {
                let timing = self.timing.unwrap_or_else(|| self.provider.timing());
                let resolvers: Vec<&str> =
                    self.fallback_resolvers.iter().map(String::as_str).collect();
                if let Err(e) =
                    wait_for_propagation(&fqdn, &dns_value, &resolvers, timing).await
                {
                    self.cleanup_all(&placed).await;
                    return Err(e);
                }
            }

            if let Err(e) = challenge.set_ready().await {
                self.cleanup_all(&placed).await;
                return Err(DnsError::Acme(e.to_string()));
            }
        }

        if let Some(delay) = self.skip_propagation {
            tokio::time::sleep(delay).await;
        }

        Ok(placed)
    }

    async fn finalize(&self, order: &mut Order) -> Result<(String, String), DnsError> {
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| DnsError::Acme(e.to_string()))?;
        if status != OrderStatus::Ready {
            return Err(DnsError::UnexpectedOrderStatus(format!("{status:?}")));
        }

        let private_key_pem = order
            .finalize()
            .await
            .map_err(|e| DnsError::Acme(e.to_string()))?;
        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| DnsError::Acme(e.to_string()))?;

        Ok((cert_chain_pem, private_key_pem))
    }

    async fn cleanup_all(&self, placed: &[PlacedRecord]) {
        for record in placed {
            let _ = self.provider.cleanup(&record.fqdn, &record.value).await;
        }
    }
}

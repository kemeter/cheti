use std::time::Duration;

use instant_acme::{
    AuthorizationStatus, ChallengeType, Identifier, Order, OrderStatus, RetryPolicy,
};

use crate::dns::wait_for_propagation;
use crate::error::DnsError;
use crate::provider::{DnsProvider, PropagationTiming};

/// One DNS-01 challenge worth presenting. Owned so it can flow through the
/// `ChallengeDriver` API without borrowing the underlying ACME order.
pub(crate) struct Dns01Challenge {
    /// Kept for diagnostics and for fake drivers; the solver itself uses fqdn.
    #[allow(dead_code)]
    pub domain: String,
    pub fqdn: String,
    pub dns_value: String,
    /// Index back into the driver — opaque to the solver.
    pub token: usize,
}

/// Abstraction over the ACME order side of the DNS-01 flow.
///
/// The solver consumes a driver instead of a concrete `instant_acme::Order`
/// so that tests can drive each path (provider failure, propagation timeout,
/// set_ready failure, finalize failure, already-valid authorization) without
/// running a real ACME server. Production callers use `InstantAcmeDriver`,
/// which wraps `instant_acme::Order` faithfully.
pub(crate) trait ChallengeDriver {
    /// Yield the next pending DNS-01 challenge, or `None` when exhausted.
    /// `Some(Ok(None))` means "this authorization is already Valid, skip it";
    /// returning `None` ends iteration. Authorizations in other terminal
    /// states yield an error.
    async fn next_dns01(&mut self) -> Option<Result<Dns01Challenge, DnsError>>;

    /// Tell the ACME server that the TXT record is in place.
    async fn set_ready(&mut self, token: usize) -> Result<(), DnsError>;

    /// Poll until the order is Ready, then finalize and fetch the cert chain.
    /// Returns `(certificate_chain_pem, private_key_pem)`.
    async fn finalize(&mut self) -> Result<(String, String), DnsError>;
}

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
    pub async fn solve_and_finalize(&self, order: Order) -> Result<(String, String), DnsError> {
        let driver = InstantAcmeDriver::new(order);
        self.solve_with_driver(driver).await
    }

    pub(crate) async fn solve_with_driver<D: ChallengeDriver>(
        &self,
        mut driver: D,
    ) -> Result<(String, String), DnsError> {
        let placed = match self.present_all(&mut driver).await {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        let outcome = driver.finalize().await;
        self.cleanup_all(&placed).await;
        outcome
    }

    async fn present_all<D: ChallengeDriver>(
        &self,
        driver: &mut D,
    ) -> Result<Vec<PlacedRecord>, DnsError> {
        let mut placed: Vec<PlacedRecord> = Vec::new();

        while let Some(result) = driver.next_dns01().await {
            let challenge = match result {
                Ok(c) => c,
                Err(e) => {
                    self.cleanup_all(&placed).await;
                    return Err(e);
                }
            };

            if let Err(e) = self
                .provider
                .present(&challenge.fqdn, &challenge.dns_value)
                .await
            {
                self.cleanup_all(&placed).await;
                return Err(e);
            }
            placed.push(PlacedRecord {
                fqdn: challenge.fqdn.clone(),
                value: challenge.dns_value.clone(),
            });

            if self.skip_propagation.is_none() {
                let timing = self.timing.unwrap_or_else(|| self.provider.timing());
                let resolvers: Vec<&str> =
                    self.fallback_resolvers.iter().map(String::as_str).collect();
                if let Err(e) =
                    wait_for_propagation(&challenge.fqdn, &challenge.dns_value, &resolvers, timing)
                        .await
                {
                    self.cleanup_all(&placed).await;
                    return Err(e);
                }
            }

            if let Err(e) = driver.set_ready(challenge.token).await {
                self.cleanup_all(&placed).await;
                return Err(e);
            }
        }

        if let Some(delay) = self.skip_propagation {
            tokio::time::sleep(delay).await;
        }

        Ok(placed)
    }

    async fn cleanup_all(&self, placed: &[PlacedRecord]) {
        for record in placed {
            let _ = self.provider.cleanup(&record.fqdn, &record.value).await;
        }
    }
}

/// Production `ChallengeDriver` that wraps an `instant_acme::Order`.
///
/// Iterates the order's authorizations once, surfacing each pending DNS-01
/// challenge as a `Dns01Challenge` owned by the solver. The token returned in
/// the challenge is the index into `pending_ready`, which holds the data
/// needed to look the challenge back up when `set_ready` is called.
pub(crate) struct InstantAcmeDriver {
    order: Order,
    /// `(authorization_index, challenge_token_url)` — empty entries (already
    /// served `set_ready`) are kept in place so token indices remain stable.
    pending_ready: Vec<Option<String>>,
    authz_cursor: usize,
}

impl InstantAcmeDriver {
    pub(crate) fn new(order: Order) -> Self {
        Self {
            order,
            pending_ready: Vec::new(),
            authz_cursor: 0,
        }
    }
}

impl ChallengeDriver for InstantAcmeDriver {
    async fn next_dns01(&mut self) -> Option<Result<Dns01Challenge, DnsError>> {
        let mut authorizations = self.order.authorizations();

        // Skip past authorizations we've already yielded.
        for _ in 0..self.authz_cursor {
            match authorizations.next().await? {
                Ok(_) => {}
                Err(e) => return Some(Err(DnsError::Acme(e.to_string()))),
            }
        }

        loop {
            let mut authz = match authorizations.next().await? {
                Ok(a) => a,
                Err(e) => return Some(Err(DnsError::Acme(e.to_string()))),
            };
            self.authz_cursor += 1;

            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => {
                    self.pending_ready.push(None);
                    continue;
                }
                other => {
                    return Some(Err(DnsError::ChallengeInvalid(format!("{other:?}"))));
                }
            }

            let domain = match &authz.identifier().identifier {
                Identifier::Dns(d) => d.clone(),
                other => {
                    return Some(Err(DnsError::Other(format!(
                        "unsupported identifier type: {other:?}"
                    ))));
                }
            };

            let challenge = match authz.challenge(ChallengeType::Dns01) {
                Some(c) => c,
                None => return Some(Err(DnsError::NoDns01Challenge(domain))),
            };

            let dns_value = challenge.key_authorization().dns_value();
            let fqdn = format!("_acme-challenge.{domain}");
            let url = challenge.url.clone();

            let token = self.pending_ready.len();
            self.pending_ready.push(Some(url));

            return Some(Ok(Dns01Challenge {
                domain,
                fqdn,
                dns_value,
                token,
            }));
        }
    }

    async fn set_ready(&mut self, token: usize) -> Result<(), DnsError> {
        let target_url = self
            .pending_ready
            .get(token)
            .and_then(|o| o.as_ref())
            .ok_or_else(|| DnsError::Other(format!("invalid challenge token {token}")))?
            .clone();

        // Find the challenge again by re-iterating; instant_acme borrows from
        // Order so we can't keep a handle across awaits.
        let mut authorizations = self.order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| DnsError::Acme(e.to_string()))?;
            if let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) {
                if challenge.url == target_url {
                    return challenge
                        .set_ready()
                        .await
                        .map_err(|e| DnsError::Acme(e.to_string()));
                }
            }
        }
        Err(DnsError::Other(format!(
            "challenge {target_url} disappeared from order"
        )))
    }

    async fn finalize(&mut self) -> Result<(String, String), DnsError> {
        let status = self
            .order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| DnsError::Acme(e.to_string()))?;
        if status != OrderStatus::Ready {
            return Err(DnsError::UnexpectedOrderStatus(format!("{status:?}")));
        }

        let private_key_pem = self
            .order
            .finalize()
            .await
            .map_err(|e| DnsError::Acme(e.to_string()))?;
        let cert_chain_pem = self
            .order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| DnsError::Acme(e.to_string()))?;

        Ok((cert_chain_pem, private_key_pem))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::provider::{DnsProvider, PropagationTiming};

    #[derive(Debug, Clone, PartialEq)]
    enum Call {
        Present(String, String),
        Cleanup(String, String),
    }

    struct FakeProvider {
        calls: Mutex<Vec<Call>>,
        present_fails_on: Option<String>,
    }

    impl FakeProvider {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                present_fails_on: None,
            }
        }

        fn fails_present_for(domain: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                present_fails_on: Some(format!("_acme-challenge.{domain}")),
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }

        fn presented_fqdns(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Present(f, _) => Some(f),
                    _ => None,
                })
                .collect()
        }

        fn cleaned_fqdns(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Cleanup(f, _) => Some(f),
                    _ => None,
                })
                .collect()
        }
    }

    impl DnsProvider for FakeProvider {
        async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Present(fqdn.to_string(), value.to_string()));
            if self.present_fails_on.as_deref() == Some(fqdn) {
                return Err(DnsError::Api("forced failure".into()));
            }
            Ok(())
        }

        async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Cleanup(fqdn.to_string(), value.to_string()));
            Ok(())
        }

        fn timing(&self) -> PropagationTiming {
            PropagationTiming {
                timeout: Duration::from_millis(50),
                interval: Duration::from_millis(5),
            }
        }
    }

    /// Scriptable challenges. Each entry is either a real Dns01 challenge to
    /// be yielded, or a directive (already-valid skip, or error).
    #[derive(Clone)]
    enum Scripted {
        Pending { domain: String },
        AlreadyValid,
        ErrorOnIter(String),
    }

    struct FakeDriver {
        script: Vec<Scripted>,
        cursor: usize,
        set_ready_fail_on: Option<usize>,
        finalize_result: Option<Result<(String, String), DnsError>>,
        set_ready_calls: Mutex<Vec<usize>>,
        finalize_called: Mutex<bool>,
    }

    impl FakeDriver {
        fn new(script: Vec<Scripted>) -> Self {
            Self {
                script,
                cursor: 0,
                set_ready_fail_on: None,
                finalize_result: Some(Ok(("CERT".into(), "KEY".into()))),
                set_ready_calls: Mutex::new(Vec::new()),
                finalize_called: Mutex::new(false),
            }
        }

        fn fail_set_ready_at(mut self, token: usize) -> Self {
            self.set_ready_fail_on = Some(token);
            self
        }

        fn fail_finalize(mut self, err: DnsError) -> Self {
            self.finalize_result = Some(Err(err));
            self
        }
    }

    impl ChallengeDriver for FakeDriver {
        async fn next_dns01(&mut self) -> Option<Result<Dns01Challenge, DnsError>> {
            loop {
                let entry = self.script.get(self.cursor)?.clone();
                let token = self.cursor;
                self.cursor += 1;
                match entry {
                    Scripted::Pending { domain } => {
                        return Some(Ok(Dns01Challenge {
                            fqdn: format!("_acme-challenge.{domain}"),
                            dns_value: format!("value-for-{domain}"),
                            domain,
                            token,
                        }));
                    }
                    Scripted::AlreadyValid => continue,
                    Scripted::ErrorOnIter(msg) => return Some(Err(DnsError::Acme(msg))),
                }
            }
        }

        async fn set_ready(&mut self, token: usize) -> Result<(), DnsError> {
            self.set_ready_calls.lock().unwrap().push(token);
            if self.set_ready_fail_on == Some(token) {
                return Err(DnsError::Acme("forced set_ready failure".into()));
            }
            Ok(())
        }

        async fn finalize(&mut self) -> Result<(String, String), DnsError> {
            *self.finalize_called.lock().unwrap() = true;
            self.finalize_result
                .take()
                .unwrap_or_else(|| Err(DnsError::Other("finalize called twice".into())))
        }
    }

    fn solver(provider: FakeProvider) -> Dns01Solver<FakeProvider> {
        // skip_propagation_check(0) bypasses wait_for_propagation, which would
        // otherwise try to resolve authoritative NS over the real network.
        Dns01Solver::new(provider).skip_propagation_check(Duration::ZERO)
    }

    #[tokio::test]
    async fn happy_path_presents_then_cleans_all() {
        let provider = FakeProvider::new();
        let driver = FakeDriver::new(vec![
            Scripted::Pending {
                domain: "a.example".into(),
            },
            Scripted::Pending {
                domain: "b.example".into(),
            },
        ]);

        let result = solver(provider).solve_with_driver(driver).await;
        let (cert, key) = result.unwrap();
        assert_eq!(cert, "CERT");
        assert_eq!(key, "KEY");
    }

    #[tokio::test]
    async fn provider_failure_midway_cleans_already_placed() {
        // First present succeeds, second fails. Expect: 1 cleanup for the
        // first record. We can't observe the provider after move, so use Arc.
        use std::sync::Arc;

        let provider = Arc::new(FakeProvider::fails_present_for("b.example"));
        let driver = FakeDriver::new(vec![
            Scripted::Pending {
                domain: "a.example".into(),
            },
            Scripted::Pending {
                domain: "b.example".into(),
            },
        ]);

        // Solver takes ownership; wrap in a struct that derefs through Arc.
        struct ArcProvider(Arc<FakeProvider>);
        impl DnsProvider for ArcProvider {
            async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.present(fqdn, value).await
            }
            async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.cleanup(fqdn, value).await
            }
            fn timing(&self) -> PropagationTiming {
                self.0.timing()
            }
        }

        let solver =
            Dns01Solver::new(ArcProvider(provider.clone())).skip_propagation_check(Duration::ZERO);
        let result = solver.solve_with_driver(driver).await;
        assert!(matches!(result, Err(DnsError::Api(_))));

        assert_eq!(
            provider.presented_fqdns(),
            vec!["_acme-challenge.a.example", "_acme-challenge.b.example"]
        );
        assert_eq!(
            provider.cleaned_fqdns(),
            vec!["_acme-challenge.a.example"],
            "only the successfully-placed record must be cleaned"
        );
    }

    #[tokio::test]
    async fn set_ready_failure_cleans_up() {
        use std::sync::Arc;
        let provider = Arc::new(FakeProvider::new());
        let driver = FakeDriver::new(vec![
            Scripted::Pending {
                domain: "a.example".into(),
            },
            Scripted::Pending {
                domain: "b.example".into(),
            },
        ])
        .fail_set_ready_at(1);

        struct ArcProvider(Arc<FakeProvider>);
        impl DnsProvider for ArcProvider {
            async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.present(fqdn, value).await
            }
            async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.cleanup(fqdn, value).await
            }
            fn timing(&self) -> PropagationTiming {
                self.0.timing()
            }
        }

        let solver =
            Dns01Solver::new(ArcProvider(provider.clone())).skip_propagation_check(Duration::ZERO);
        let result = solver.solve_with_driver(driver).await;
        assert!(matches!(result, Err(DnsError::Acme(_))));

        assert_eq!(
            provider.cleaned_fqdns(),
            vec!["_acme-challenge.a.example", "_acme-challenge.b.example"],
            "both records placed before set_ready failed must be cleaned"
        );
    }

    #[tokio::test]
    async fn finalize_failure_still_cleans_up() {
        use std::sync::Arc;
        let provider = Arc::new(FakeProvider::new());
        let driver = FakeDriver::new(vec![Scripted::Pending {
            domain: "a.example".into(),
        }])
        .fail_finalize(DnsError::Acme("CA exploded".into()));

        struct ArcProvider(Arc<FakeProvider>);
        impl DnsProvider for ArcProvider {
            async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.present(fqdn, value).await
            }
            async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.cleanup(fqdn, value).await
            }
            fn timing(&self) -> PropagationTiming {
                self.0.timing()
            }
        }

        let solver =
            Dns01Solver::new(ArcProvider(provider.clone())).skip_propagation_check(Duration::ZERO);
        let result = solver.solve_with_driver(driver).await;
        assert!(matches!(result, Err(DnsError::Acme(_))));
        assert_eq!(
            provider.cleaned_fqdns(),
            vec!["_acme-challenge.a.example"],
            "cleanup must run even when finalize fails"
        );
    }

    #[tokio::test]
    async fn already_valid_authorization_is_skipped() {
        use std::sync::Arc;
        let provider = Arc::new(FakeProvider::new());
        let driver = FakeDriver::new(vec![
            Scripted::AlreadyValid,
            Scripted::Pending {
                domain: "a.example".into(),
            },
        ]);

        struct ArcProvider(Arc<FakeProvider>);
        impl DnsProvider for ArcProvider {
            async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.present(fqdn, value).await
            }
            async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.cleanup(fqdn, value).await
            }
            fn timing(&self) -> PropagationTiming {
                self.0.timing()
            }
        }

        let solver =
            Dns01Solver::new(ArcProvider(provider.clone())).skip_propagation_check(Duration::ZERO);
        let (cert, _) = solver.solve_with_driver(driver).await.unwrap();
        assert_eq!(cert, "CERT");

        // Only the pending authorization should have been presented.
        assert_eq!(
            provider.presented_fqdns(),
            vec!["_acme-challenge.a.example"]
        );
        assert_eq!(provider.cleaned_fqdns(), vec!["_acme-challenge.a.example"]);
    }

    #[tokio::test]
    async fn iteration_error_cleans_up_already_placed() {
        use std::sync::Arc;
        let provider = Arc::new(FakeProvider::new());
        let driver = FakeDriver::new(vec![
            Scripted::Pending {
                domain: "a.example".into(),
            },
            Scripted::ErrorOnIter("network glitch".into()),
        ]);

        struct ArcProvider(Arc<FakeProvider>);
        impl DnsProvider for ArcProvider {
            async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.present(fqdn, value).await
            }
            async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.cleanup(fqdn, value).await
            }
            fn timing(&self) -> PropagationTiming {
                self.0.timing()
            }
        }

        let solver =
            Dns01Solver::new(ArcProvider(provider.clone())).skip_propagation_check(Duration::ZERO);
        let result = solver.solve_with_driver(driver).await;
        assert!(matches!(result, Err(DnsError::Acme(_))));
        assert_eq!(
            provider.cleaned_fqdns(),
            vec!["_acme-challenge.a.example"],
            "the one record placed before the iteration error must be cleaned"
        );
    }
}

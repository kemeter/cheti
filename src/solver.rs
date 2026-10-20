use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use instant_acme::{
    AuthorizationStatus, ChallengeType, Identifier, Order, OrderStatus, RetryPolicy,
};

use crate::cleanup::CleanupGuard;
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

    /// Tell the ACME server that the TXT records of these challenges are in
    /// place, in one go.
    async fn set_ready(&mut self, tokens: &[usize]) -> Result<(), DnsError>;

    /// Poll until the order is Ready, then finalize and fetch the cert chain.
    /// Returns `(certificate_chain_pem, private_key_pem)`.
    async fn finalize(&mut self) -> Result<(String, String), DnsError>;
}

#[derive(Clone)]
struct PlacedRecord {
    fqdn: String,
    value: String,
}

/// End-to-end DNS-01 orchestrator. Wraps a `DnsProvider` and drives an
/// `instant_acme::Order` from `Pending` to a usable certificate, calling
/// `present` / `cleanup` on the provider as needed.
pub struct Dns01Solver<P: DnsProvider + 'static> {
    provider: Arc<P>,
    fallback_resolvers: Vec<String>,
    timing: Option<PropagationTiming>,
    skip_propagation: Option<Duration>,
}

impl<P: DnsProvider + 'static> Dns01Solver<P> {
    /// Solve with `provider`, using the default public resolvers as fallback.
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
            fallback_resolvers: crate::dns::DEFAULT_RESOLVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            timing: None,
            skip_propagation: None,
        }
    }

    /// Resolvers (`ip:port`) polled when the zone's authoritative nameservers
    /// cannot be found.
    pub fn with_resolvers(mut self, resolvers: Vec<impl Into<String>>) -> Self {
        self.fallback_resolvers = resolvers.into_iter().map(Into::into).collect();
        self
    }

    /// Overrides the provider's propagation timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timing
            .get_or_insert_with(PropagationTiming::default)
            .timeout = timeout;
        self
    }

    /// Overrides the provider's propagation polling interval.
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
    /// `(certificate_chain_pem, private_key_pem)`.
    ///
    /// Placed TXT records are removed before returning, on success and on
    /// error. If this future is dropped before completing (a caller-side
    /// timeout, a `select!`, a shutdown), the records still in place are
    /// removed from a task spawned on the current Tokio runtime. Cleanup is
    /// best-effort either way: a failing `cleanup` is not reported, and the
    /// spawned task does not run if the runtime shuts down first.
    pub async fn solve_and_finalize(&self, order: Order) -> Result<(String, String), DnsError> {
        let driver = InstantAcmeDriver::new(order);
        self.solve_with_driver(driver).await
    }

    pub(crate) async fn solve_with_driver<D: ChallengeDriver>(
        &self,
        mut driver: D,
    ) -> Result<(String, String), DnsError> {
        let mut placed = self.cleanup_guard();
        let outcome = match self.present_then_ready(&mut driver, &mut placed).await {
            Ok(()) => driver.finalize().await,
            Err(e) => Err(e),
        };
        placed.run().await;
        outcome
    }

    fn cleanup_guard(&self) -> CleanupGuard<PlacedRecord> {
        let provider = Arc::clone(&self.provider);
        CleanupGuard::new(move |record: PlacedRecord| {
            let provider = Arc::clone(&provider);
            async move {
                let _ = provider.cleanup(&record.fqdn, &record.value).await;
            }
        })
    }

    /// Places every record first, then waits for propagation once, and only
    /// then tells ACME to validate: no challenge is set ready before its
    /// record is visible, and the wait is not paid once per challenge.
    async fn present_then_ready<D: ChallengeDriver>(
        &self,
        driver: &mut D,
        placed: &mut CleanupGuard<PlacedRecord>,
    ) -> Result<(), DnsError> {
        let mut tokens: Vec<usize> = Vec::new();

        while let Some(result) = driver.next_dns01().await {
            let challenge = result?;
            // Recorded before `present`: a provider can create the record and
            // still fail afterwards (timeout, follow-up call), and cleanup is
            // idempotent, so a record that was never written costs nothing.
            placed.push(PlacedRecord {
                fqdn: challenge.fqdn.clone(),
                value: challenge.dns_value.clone(),
            });
            self.provider
                .present(&challenge.fqdn, &challenge.dns_value)
                .await?;
            tokens.push(challenge.token);
        }

        match self.skip_propagation {
            Some(delay) => tokio::time::sleep(delay).await,
            None => {
                let timing = self.timing.unwrap_or_else(|| self.provider.timing());
                let resolvers: Vec<&str> =
                    self.fallback_resolvers.iter().map(String::as_str).collect();
                for record in placed.pending() {
                    wait_for_propagation(&record.fqdn, &record.value, &resolvers, timing).await?;
                }
            }
        }

        driver.set_ready(&tokens).await
    }
}

/// Production `ChallengeDriver` that wraps an `instant_acme::Order`.
///
/// Each authorization is an HTTP fetch, and instant_acme's challenge handles
/// borrow the order, so none can be kept between calls. The driver therefore
/// reads every authorization once to collect the pending DNS-01 challenges,
/// and once more to set them all ready: two passes whatever the number of
/// identifiers. A challenge's token is its index in `challenge_urls`.
pub(crate) struct InstantAcmeDriver {
    order: Order,
    /// Challenges (or the error that ended collection) not yielded yet;
    /// `None` until the first `next_dns01`.
    queue: Option<VecDeque<Result<Dns01Challenge, DnsError>>>,
    challenge_urls: Vec<String>,
}

impl InstantAcmeDriver {
    pub(crate) fn new(order: Order) -> Self {
        Self {
            order,
            queue: None,
            challenge_urls: Vec::new(),
        }
    }

    /// Reads every authorization once. Collection stops at the first error,
    /// which is queued after the challenges found before it.
    async fn collect(&mut self) -> VecDeque<Result<Dns01Challenge, DnsError>> {
        let mut queue = VecDeque::new();
        let mut authorizations = self.order.authorizations();
        while let Some(result) = authorizations.next().await {
            match Self::pending_challenge(result, &mut self.challenge_urls) {
                Ok(Some(challenge)) => queue.push_back(Ok(challenge)),
                Ok(None) => {}
                Err(e) => {
                    queue.push_back(Err(e));
                    break;
                }
            }
        }
        queue
    }

    /// The DNS-01 challenge of a pending authorization, `None` for one that is
    /// already valid.
    fn pending_challenge(
        result: Result<instant_acme::AuthorizationHandle<'_>, instant_acme::Error>,
        challenge_urls: &mut Vec<String>,
    ) -> Result<Option<Dns01Challenge>, DnsError> {
        let mut authz = result.map_err(|e| DnsError::Acme(e.to_string()))?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => return Ok(None),
            other => return Err(DnsError::ChallengeInvalid(format!("{other:?}"))),
        }

        let domain = match &authz.identifier().identifier {
            Identifier::Dns(d) => d.clone(),
            other => {
                return Err(DnsError::Other(format!(
                    "unsupported identifier type: {other:?}"
                )));
            }
        };

        let challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| DnsError::NoDns01Challenge(domain.clone()))?;

        let token = challenge_urls.len();
        challenge_urls.push(challenge.url.clone());
        Ok(Some(Dns01Challenge {
            fqdn: format!("_acme-challenge.{domain}"),
            dns_value: challenge.key_authorization().dns_value(),
            domain,
            token,
        }))
    }
}

impl ChallengeDriver for InstantAcmeDriver {
    async fn next_dns01(&mut self) -> Option<Result<Dns01Challenge, DnsError>> {
        if self.queue.is_none() {
            self.queue = Some(self.collect().await);
        }
        self.queue.as_mut()?.pop_front()
    }

    async fn set_ready(&mut self, tokens: &[usize]) -> Result<(), DnsError> {
        let mut targets: Vec<&str> = Vec::with_capacity(tokens.len());
        for token in tokens {
            let url = self
                .challenge_urls
                .get(*token)
                .ok_or_else(|| DnsError::Other(format!("invalid challenge token {token}")))?;
            targets.push(url);
        }

        let mut authorizations = self.order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| DnsError::Acme(e.to_string()))?;
            if let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) {
                if let Some(pos) = targets.iter().position(|url| *url == challenge.url) {
                    challenge
                        .set_ready()
                        .await
                        .map_err(|e| DnsError::Acme(e.to_string()))?;
                    targets.swap_remove(pos);
                }
            }
        }
        match targets.first() {
            None => Ok(()),
            Some(url) => Err(DnsError::Other(format!(
                "challenge {url} disappeared from order"
            ))),
        }
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

    #[async_trait::async_trait]
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

        async fn set_ready(&mut self, tokens: &[usize]) -> Result<(), DnsError> {
            for token in tokens {
                self.set_ready_calls.lock().unwrap().push(*token);
                if self.set_ready_fail_on == Some(*token) {
                    return Err(DnsError::Acme("forced set_ready failure".into()));
                }
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
        #[async_trait::async_trait]
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
            vec!["_acme-challenge.a.example", "_acme-challenge.b.example"],
            "a failed present may have written its record, so it is cleaned too"
        );
    }

    #[tokio::test]
    async fn every_record_is_placed_before_any_challenge_is_set_ready() {
        use std::sync::Arc;

        // Records the interleaving of provider and driver calls.
        let events = Arc::new(Mutex::new(Vec::<String>::new()));

        struct RecordingProvider(Arc<Mutex<Vec<String>>>);
        #[async_trait::async_trait]
        impl DnsProvider for RecordingProvider {
            async fn present(&self, fqdn: &str, _value: &str) -> Result<(), DnsError> {
                self.0.lock().unwrap().push(format!("present {fqdn}"));
                Ok(())
            }
            async fn cleanup(&self, _fqdn: &str, _value: &str) -> Result<(), DnsError> {
                Ok(())
            }
        }

        struct RecordingDriver {
            inner: FakeDriver,
            events: Arc<Mutex<Vec<String>>>,
        }
        impl ChallengeDriver for RecordingDriver {
            async fn next_dns01(&mut self) -> Option<Result<Dns01Challenge, DnsError>> {
                self.inner.next_dns01().await
            }
            async fn set_ready(&mut self, tokens: &[usize]) -> Result<(), DnsError> {
                for token in tokens {
                    self.events.lock().unwrap().push(format!("ready {token}"));
                }
                self.inner.set_ready(tokens).await
            }
            async fn finalize(&mut self) -> Result<(String, String), DnsError> {
                self.inner.finalize().await
            }
        }

        let driver = RecordingDriver {
            inner: FakeDriver::new(vec![
                Scripted::Pending {
                    domain: "a.example".into(),
                },
                Scripted::Pending {
                    domain: "b.example".into(),
                },
            ]),
            events: events.clone(),
        };

        let solver = Dns01Solver::new(RecordingProvider(events.clone()))
            .skip_propagation_check(Duration::ZERO);
        solver.solve_with_driver(driver).await.unwrap();

        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "present _acme-challenge.a.example",
                "present _acme-challenge.b.example",
                "ready 0",
                "ready 1",
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn records_are_cleaned_up_when_the_solve_is_cancelled() {
        use std::sync::Arc;

        struct ArcProvider(Arc<FakeProvider>);
        #[async_trait::async_trait]
        impl DnsProvider for ArcProvider {
            async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.present(fqdn, value).await
            }
            async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
                self.0.cleanup(fqdn, value).await
            }
        }

        let provider = Arc::new(FakeProvider::new());
        let driver = FakeDriver::new(vec![
            Scripted::Pending {
                domain: "a.example".into(),
            },
            Scripted::Pending {
                domain: "b.example".into(),
            },
        ]);
        // The propagation delay outlasts the caller's timeout, so the solve
        // is dropped after both records are placed and before any cleanup.
        let solver = Dns01Solver::new(ArcProvider(provider.clone()))
            .skip_propagation_check(Duration::from_secs(600));
        let cancelled =
            tokio::time::timeout(Duration::from_secs(1), solver.solve_with_driver(driver)).await;
        assert!(cancelled.is_err(), "the solve should have been cancelled");

        // Let the cleanup task spawned on drop run; bounded so a missing
        // cleanup fails the assertion below instead of hanging.
        for _ in 0..100 {
            if provider.cleaned_fqdns().len() >= 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            provider.cleaned_fqdns(),
            vec!["_acme-challenge.a.example", "_acme-challenge.b.example"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn skip_propagation_delay_elapses_before_set_ready() {
        use std::sync::Arc;

        let ready_at = Arc::new(Mutex::new(None));

        struct TimingDriver {
            inner: FakeDriver,
            ready_at: Arc<Mutex<Option<tokio::time::Instant>>>,
        }
        impl ChallengeDriver for TimingDriver {
            async fn next_dns01(&mut self) -> Option<Result<Dns01Challenge, DnsError>> {
                self.inner.next_dns01().await
            }
            async fn set_ready(&mut self, tokens: &[usize]) -> Result<(), DnsError> {
                *self.ready_at.lock().unwrap() = Some(tokio::time::Instant::now());
                self.inner.set_ready(tokens).await
            }
            async fn finalize(&mut self) -> Result<(String, String), DnsError> {
                self.inner.finalize().await
            }
        }

        let driver = TimingDriver {
            inner: FakeDriver::new(vec![Scripted::Pending {
                domain: "a.example".into(),
            }]),
            ready_at: ready_at.clone(),
        };

        let start = tokio::time::Instant::now();
        let solver =
            Dns01Solver::new(FakeProvider::new()).skip_propagation_check(Duration::from_secs(30));
        solver.solve_with_driver(driver).await.unwrap();

        let ready_at = ready_at.lock().unwrap().expect("set_ready was called");
        assert!(
            ready_at - start >= Duration::from_secs(30),
            "set_ready ran before the propagation delay elapsed"
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
        #[async_trait::async_trait]
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
        #[async_trait::async_trait]
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
        #[async_trait::async_trait]
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
        #[async_trait::async_trait]
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

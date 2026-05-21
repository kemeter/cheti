//! End-to-end ACME DNS-01 flow against Pebble + challtestsrv.
//!
//! Marked `#[ignore]` because it needs Pebble (port 14000) and challtestsrv
//! (port 8055 mgmt, port 8053 DNS) running. To execute:
//!
//!     # Start the stack (see scripts/pebble-up.sh for the docker invocations)
//!     cargo test --test pebble_e2e -- --ignored
//!
//! What it validates: that Dns01Solver, driving a real instant_acme::Order,
//! produces a usable certificate. This is the only test that exercises the
//! InstantAcmeDriver wrapper end-to-end.

use std::time::Duration;

use cheti::{Dns01Solver, DnsError, DnsProvider, PropagationTiming};
use instant_acme::{Account, Identifier, NewAccount, NewOrder};

const PEBBLE_DIR_URL: &str = "https://localhost:14000/dir";
const CHALLTESTSRV_MGMT: &str = "http://localhost:8055";

/// The CA that signs Pebble's WFE (`localhost:14000`) TLS certificate, baked
/// into the Pebble docker image. NOT the same as the ACME root that Pebble
/// itself issues certs against — that one is rotated every restart and only
/// reachable on port 15000 (which we never need to trust, since we don't talk
/// HTTPS to the ACME _output_).
const PEBBLE_MINICA_PEM: &str = include_str!("data/pebble.minica.pem");

/// DnsProvider that POSTs to challtestsrv's management API instead of a real
/// DNS API. Pebble's VA reads back through challtestsrv's DNS server, so this
/// is what closes the loop.
struct ChalltestsrvProvider {
    http: reqwest::Client,
    mgmt_url: String,
}

impl ChalltestsrvProvider {
    fn new(mgmt_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            mgmt_url: mgmt_url.into(),
        }
    }

    fn ensure_trailing_dot(host: &str) -> String {
        if host.ends_with('.') {
            host.to_string()
        } else {
            format!("{host}.")
        }
    }
}

impl DnsProvider for ChalltestsrvProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let body = serde_json::json!({
            "host": Self::ensure_trailing_dot(fqdn),
            "value": value,
        });
        let res = self
            .http
            .post(format!("{}/set-txt", self.mgmt_url))
            .json(&body)
            .send()
            .await
            .map_err(DnsError::Http)?;
        if !res.status().is_success() {
            return Err(DnsError::Api(format!(
                "challtestsrv set-txt returned {}",
                res.status()
            )));
        }
        Ok(())
    }

    async fn cleanup(&self, fqdn: &str, _value: &str) -> Result<(), DnsError> {
        let body = serde_json::json!({
            "host": Self::ensure_trailing_dot(fqdn),
        });
        let res = self
            .http
            .post(format!("{}/clear-txt", self.mgmt_url))
            .json(&body)
            .send()
            .await
            .map_err(DnsError::Http)?;
        if !res.status().is_success() {
            return Err(DnsError::Api(format!(
                "challtestsrv clear-txt returned {}",
                res.status()
            )));
        }
        Ok(())
    }

    fn timing(&self) -> PropagationTiming {
        PropagationTiming {
            timeout: Duration::from_secs(10),
            interval: Duration::from_millis(200),
        }
    }
}

fn pebble_minica_to_tempfile() -> std::path::PathBuf {
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("cheti-pebble-minica-{pid}.pem"));
    std::fs::write(&path, PEBBLE_MINICA_PEM).expect("write pem");
    path
}

fn install_default_crypto_provider() {
    use std::sync::Once;
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        // instant_acme pulls in rustls 0.23 which requires explicit provider
        // selection. Pebble's cert is fetched and verified with reqwest below,
        // which also routes through rustls.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[tokio::test]
#[ignore = "requires Pebble + challtestsrv on localhost"]
async fn issue_certificate_for_single_domain() {
    install_default_crypto_provider();
    let root_path = pebble_minica_to_tempfile();

    let (account, _creds) = Account::builder_with_root(&root_path)
        .expect("builder with pebble root")
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            PEBBLE_DIR_URL.to_string(),
            None,
        )
        .await
        .expect("create account against pebble");

    let identifiers = vec![Identifier::Dns("e2e.cheti.test".to_string())];
    let order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .expect("new_order");

    let provider = ChalltestsrvProvider::new(CHALLTESTSRV_MGMT);
    // skip the propagation poll: challtestsrv is in-process for Pebble's VA,
    // and our wait_for_propagation queries the public resolvers by default,
    // which would never see the TXT.
    let solver = Dns01Solver::new(provider).skip_propagation_check(Duration::from_millis(200));

    let (cert_pem, key_pem) = solver
        .solve_and_finalize(order)
        .await
        .expect("solve_and_finalize");

    assert!(
        cert_pem.contains("BEGIN CERTIFICATE"),
        "expected PEM cert, got {}",
        cert_pem.chars().take(200).collect::<String>()
    );
    assert!(key_pem.contains("BEGIN") && key_pem.contains("PRIVATE KEY"));

    let _ = std::fs::remove_file(&root_path);
}

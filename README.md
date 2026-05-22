# Cheti

> *Cheti* means "certificate" in Swahili.

ACME DNS-01 challenge library for Rust, with pluggable DNS providers.

## Features

- **DNS-01 challenges only** — works for wildcards and for domains behind a firewall, no HTTP-01 server needed
- **Built-in providers**: Cloudflare, Gandi, OVH, Scaleway
- **Bring-your-own provider**: implement the `DnsProvider` trait for anything else
- **Persisted ACME accounts** via `AccountStore` so you don't burn through your CA's account-creation rate limit
- **Renewal helper** that reads a leaf certificate's expiry and tells you when to re-issue
- **Concurrent-safe** per-FQDN, so two parallel issuances on the same record can't clobber each other
- **End-to-end tested** against [Pebble](https://github.com/letsencrypt/pebble), the official ACME test server

## Status

Early development. API may change before `0.1.0` is published to crates.io.

## Quickstart

Add to `Cargo.toml`:

```toml
[dependencies]
cheti = { git = "https://github.com/kemeter/cheti" }
instant-acme = "0.8"
tokio = { version = "1", features = ["full"] }
```

Issue a certificate for `example.com` against Let's Encrypt staging:

```rust,no_run
use cheti::{Dns01Solver, GandiConfig, GandiProvider, FileAccountStore, AccountStore};
use instant_acme::{Account, Identifier, NewAccount, NewOrder};

const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load (or create + persist) an ACME account.
    let store = FileAccountStore::new("/var/lib/cheti/account.json");
    let account = match store.load()? {
        Some(creds) => Account::builder()?.from_credentials(creds).await?,
        None => {
            let (account, creds) = Account::builder()?
                .create(
                    &NewAccount {
                        contact: &["mailto:admin@example.com"],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    LE_STAGING.to_string(),
                    None,
                )
                .await?;
            store.save(&creds)?;
            account
        }
    };

    // 2. Place an order for the identifiers you want.
    let identifiers = vec![Identifier::Dns("example.com".to_string())];
    let order = account.new_order(&NewOrder::new(&identifiers)).await?;

    // 3. Wire up your DNS provider.
    let provider = GandiProvider::new(GandiConfig::new(std::env::var("GANDI_TOKEN")?))?;

    // 4. Solve the DNS-01 challenge and grab the certificate.
    let solver = Dns01Solver::new(provider);
    let (cert_pem, key_pem) = solver.solve_and_finalize(order).await?;

    std::fs::write("/etc/ssl/example.com.crt", cert_pem)?;
    std::fs::write("/etc/ssl/example.com.key", key_pem)?;
    Ok(())
}
```

## Providers

Each provider has the same shape: a `*Config` builder, then a `*Provider` constructed from it.

### Cloudflare

Bearer token with `Zone:DNS:Edit` scope. Create it at <https://dash.cloudflare.com/profile/api-tokens>.

```rust,no_run
use cheti::{CloudflareConfig, CloudflareProvider};

let config = CloudflareConfig::new(std::env::var("CLOUDFLARE_API_TOKEN").unwrap());
let provider = CloudflareProvider::new(config).unwrap();
```

If you already know the Cloudflare zone id (saves one API call):

```rust,no_run
use cheti::CloudflareConfig;
let config = CloudflareConfig::new("token")
    .with_zone_id("example.com", "abc123zoneid").unwrap();
```

### Gandi

Personal access token from <https://account.gandi.net/en/users/_/security>. Needs DNS scope on the relevant domains.

```rust,no_run
use cheti::{GandiConfig, GandiProvider};

let config = GandiConfig::new(std::env::var("GANDIV5_PERSONAL_ACCESS_TOKEN").unwrap());
let provider = GandiProvider::new(config).unwrap();
```

### OVH

Three credentials: application key, application secret, consumer key. Create them at <https://api.ovh.com/createToken/>.

```rust,no_run
use cheti::{OvhConfig, OvhProvider};

let config = OvhConfig::new(
    std::env::var("OVH_APPLICATION_KEY").unwrap(),
    std::env::var("OVH_APPLICATION_SECRET").unwrap(),
    std::env::var("OVH_CONSUMER_KEY").unwrap(),
);
let provider = OvhProvider::new(config).unwrap();
```

### Scaleway

API secret key from <https://console.scaleway.com/iam/api-keys>. The key needs the `DNSFullAccess` permission set.

```rust,no_run
use cheti::{ScalewayConfig, ScalewayProvider};

let config = ScalewayConfig::new(std::env::var("SCW_SECRET_KEY").unwrap());
let provider = ScalewayProvider::new(config).unwrap();
```

### Skipping the SOA lookup

By default each provider calls `find_zone()` (an SOA walk) to determine which zone owns the FQDN. If you already know the zone, pass it explicitly to skip the lookup:

```rust,no_run
use cheti::{GandiConfig};
let config = GandiConfig::new("token").with_zone("example.com").unwrap();
```

## Renewal

`needs_renewal` parses the leaf certificate and returns `true` when expiry is within the threshold. An unparseable certificate also returns `true` — the safe default for a renewal gate is to re-issue:

```rust,no_run
use cheti::needs_renewal;

let cert_pem = std::fs::read_to_string("/etc/ssl/example.com.crt").unwrap();
if needs_renewal(&cert_pem, 30) {
    // Re-issue: rebuild your solver and call solve_and_finalize again.
}
```

If you need to distinguish "expiring" from "couldn't parse", use `needs_renewal_checked`, which returns `Result<bool, DnsError>`.

Hook this into a daily cron or a periodic task. For Let's Encrypt (90-day certs) a 30-day threshold is the conventional choice.

## Short-lived certificates

`instant_acme` exposes the ACME profile mechanism. Let's Encrypt and Pebble both ship a `shortlived` profile that issues 6-hour certificates:

```rust,no_run
# async fn run(account: instant_acme::Account) -> Result<(), Box<dyn std::error::Error>> {
use instant_acme::{Identifier, NewOrder};

let identifiers = vec![Identifier::Dns("example.com".to_string())];
let order = account
    .new_order(&NewOrder::new(&identifiers).profile("shortlived"))
    .await?;
# Ok(()) }
```

The solver doesn't care — set the profile on the order and pass it in.

## Propagation tuning

The solver polls authoritative nameservers until the TXT record is visible, then asks the CA to validate. Defaults (120s timeout, 5s interval) are conservative; tune for your provider:

```rust,no_run
use std::time::Duration;
use cheti::Dns01Solver;
# use cheti::{GandiConfig, GandiProvider};
# let provider = GandiProvider::new(GandiConfig::new("t")).unwrap();
let solver = Dns01Solver::new(provider)
    .with_timeout(Duration::from_secs(60))
    .with_interval(Duration::from_secs(2));
```

If your DNS provider's authoritative servers lag (anycast, split-horizon), you can bypass the active poll:

```rust,no_run
# use std::time::Duration;
# use cheti::{Dns01Solver, GandiConfig, GandiProvider};
# let provider = GandiProvider::new(GandiConfig::new("t")).unwrap();
let solver = Dns01Solver::new(provider)
    .skip_propagation_check(Duration::from_secs(30));
```

This blindly sleeps instead of verifying — only use when the safety net is the problem.

## Local development with Pebble

The e2e test suite runs against [Pebble](https://github.com/letsencrypt/pebble) (the official ACME test CA) plus its DNS challenge server. To run it locally:

```sh
./scripts/pebble-up.sh
cargo test --test pebble_e2e -- --ignored
./scripts/pebble-down.sh
```

This is the only test that exercises the full `Dns01Solver` → `instant_acme::Order` flow; the rest of the suite uses wiremock against each provider's HTTP API.

## Implementing a custom provider

```rust
use async_trait::async_trait;
use cheti::{DnsError, DnsProvider};

struct MyProvider { /* ... */ }

#[async_trait]
impl DnsProvider for MyProvider {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        // Create or update a TXT record at `fqdn` containing `value`.
        // If the record already has other values, preserve them.
        todo!()
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        // Remove `value` from the TXT record at `fqdn`. If that empties
        // the record entirely, delete the record.
        todo!()
    }
}
```

The trait uses [`async_trait`](https://docs.rs/async-trait), so annotate your impl with `#[async_trait]`. Being object-safe, providers can also be used as `Box<dyn DnsProvider>` when the concrete type is chosen at runtime.

`present` must be **idempotent** (re-calling with the same value is a no-op) and **concurrent-safe** per `fqdn`. The built-in providers use a `KeyedMutex` for the latter — feel free to copy the pattern.

## License

MIT.

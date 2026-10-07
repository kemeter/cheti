# Cheti

> *Cheti* means "certificate" in Swahili.

ACME DNS-01 challenge library for Rust, with pluggable DNS providers.

## Features

- **DNS-01 challenges only** — works for wildcards and for domains behind a firewall, no HTTP-01 server needed
- **Built-in providers**: Cloudflare, deSEC, DigitalOcean, Gandi, Hetzner, OVH, Porkbun, Scaleway, and RFC 2136 (TSIG-signed dynamic updates) for self-hosted servers such as BIND, Knot DNS or PowerDNS
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

### deSEC

API token from <https://desec.io/tokens>. The zone is resolved through the deSEC API (`owns_qname`), so no SOA lookup is needed. Records are written with a TTL of 3600s (or the domain's minimum TTL if higher), as deSEC rejects lower values for most accounts. deSEC rate-limits RRset writes per domain; a throttled request fails with an error carrying the `Retry-After` delay.

```rust,no_run
use cheti::{DesecConfig, DesecProvider};

let config = DesecConfig::new(std::env::var("DESEC_TOKEN").unwrap());
let provider = DesecProvider::new(config).unwrap();
```

### DigitalOcean

Personal access token from <https://cloud.digitalocean.com/account/api/tokens>, with read and write access to domains. Each challenge value is stored as its own TXT record (TTL 30s, the minimum DigitalOcean accepts), so a wildcard and an apex challenge on the same name don't interfere, and cleanup only deletes the record holding its own value. The zone must be a domain managed in the DigitalOcean account.

```rust,no_run
use cheti::{DigitalOceanConfig, DigitalOceanProvider};

let config = DigitalOceanConfig::new(std::env::var("DIGITALOCEAN_TOKEN").unwrap());
let provider = DigitalOceanProvider::new(config).unwrap();
```

`DigitalOceanProvider::from_env()` reads the token from `DIGITALOCEAN_TOKEN`.

### Gandi

Personal access token from <https://account.gandi.net/en/users/_/security>. Needs DNS scope on the relevant domains.

```rust,no_run
use cheti::{GandiConfig, GandiProvider};

let config = GandiConfig::new(std::env::var("GANDIV5_PERSONAL_ACCESS_TOKEN").unwrap());
let provider = GandiProvider::new(config).unwrap();
```

### Hetzner

API token of the Hetzner Console project that holds the zone, with read & write permission. Create it in the [Hetzner Console](https://console.hetzner.com/) under `Security` → `API Tokens`. Records are managed through the zones API of the Hetzner Cloud API; the legacy DNS Console API (`dns.hetzner.com`) is not supported, as it has been shut down. The zone is resolved through the API, so no SOA lookup is needed. A new TXT RRSet is created with a TTL of 60s; an existing one keeps its TTL. Record changes are asynchronous actions, which the provider waits for (up to 60s) before returning.

```rust,no_run
use cheti::{HetznerConfig, HetznerProvider};

let config = HetznerConfig::new(std::env::var("HETZNER_API_TOKEN").unwrap());
let provider = HetznerProvider::new(config).unwrap();
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

### Porkbun

API key and secret API key from <https://porkbun.com/account/api>. API access must also be turned on for each domain (domain management page, "API Access"); otherwise every call fails with an authentication error naming the domain. Porkbun has no endpoint telling which domain owns a name, so the zone is found with the SOA lookup unless given through `with_zone`. Each challenge value is its own TXT record, written with a TTL of 600s (the Porkbun minimum), so a wildcard and its apex can be validated at the same time. Porkbun accepts writes even for a domain delegated to other nameservers; `present` fails (and removes the record) when Porkbun reports that the record will not resolve.

```rust,no_run
use cheti::{PorkbunConfig, PorkbunProvider};

let config = PorkbunConfig::new(
    std::env::var("PORKBUN_API_KEY").unwrap(),
    std::env::var("PORKBUN_SECRET_API_KEY").unwrap(),
);
let provider = PorkbunProvider::new(config).unwrap();
```

`PorkbunProvider::from_env()` reads the same two variables.

### RFC 2136 (BIND, Knot DNS, PowerDNS, ...)

Sends TSIG-signed dynamic updates (RFC 2136) over TCP to the zone's primary server. Supported TSIG algorithms are `hmac-sha256` (default), `hmac-sha384` and `hmac-sha512`; `hmac-sha1` and `hmac-md5` are not. Each `present` adds a single TXT record and each `cleanup` deletes only that record, so other values on the same name (e.g. wildcard + apex issuance) are left alone.

```rust,no_run
use cheti::{Rfc2136Config, Rfc2136Provider, TsigAlgorithm};

let config = Rfc2136Config::new(
    "ns1.example.com:53",        // host, ip, host:port or [ipv6]:port; port defaults to 53
    "acme-update",               // TSIG key name, as declared on the server
    std::env::var("RFC2136_TSIG_SECRET").unwrap(), // base64 secret
)
.with_algorithm(TsigAlgorithm::HmacSha512);
let provider = Rfc2136Provider::new(config).unwrap();
```

`Rfc2136Provider::from_env()` reads `RFC2136_NAMESERVER`, `RFC2136_TSIG_KEY`, `RFC2136_TSIG_SECRET` and the optional `RFC2136_TSIG_ALGORITHM`. Records are written with a 60s TTL (`with_ttl` to change it), and each update exchange times out after 10s (`with_timeout`). The zone is found with an SOA lookup through the system resolvers; for internal or split-horizon zones, set it with `with_zone`.

The key needs permission to update TXT records under the zone. With BIND:

```text
key "acme-update" {
    algorithm hmac-sha256;
    secret "<base64 secret, e.g. from `tsig-keygen acme-update`>";
};

zone "example.com" {
    type primary;
    file "/var/lib/bind/example.com.zone";
    update-policy {
        grant acme-update zonesub TXT;
    };
};
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

The RFC 2136 provider is tested against an in-process mock server, and optionally against a real BIND primary:

```sh
./scripts/bind-up.sh
cargo test --test rfc2136_bind -- --ignored
./scripts/bind-down.sh
```

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

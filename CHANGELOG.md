# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `providers::from_env(name)`, building a provider from its name and its
  environment variables, as Traefik and lego pick one from a name alone.
  It takes lego's names for providers too (`gandiv5`, `pdns`, `gcloud`);
  `providers::NAMES` lists them. `providers::from_env_with` reads the
  variables through a function instead, to take one under another name or
  from configuration.
- `RFC2136_ZONE` in `Rfc2136Provider::from_env`.
- Every provider's `from_env` reads lego's variable names where they differ
  from cheti's (`CF_DNS_API_TOKEN`, `DO_AUTH_TOKEN`, `PDNS_*`,
  `SCALEWAY_API_TOKEN`, `GCE_SERVICE_ACCOUNT`, `GCE_SERVICE_ACCOUNT_FILE`,
  `GCE_PROJECT`), and each variable from the file its `<NAME>_FILE` variable
  names, as Docker and Kubernetes secrets are mounted.
- `OvhConfig::with_endpoint`, taking an endpoint by name as OVH's SDKs and
  lego do (`ovh-eu`, `ovh-ca`, `ovh-us`, `kimsufi-*`, `soyoustart-*`), and
  `OVH_ENDPOINT` in `OvhProvider::from_env`.

## [0.1.1] - 2026-11-06

### Added

- `on_cleanup_error` on `Dns01Solver` and `TlsAlpn01Solver`, called with the
  name and the error when removing challenge material fails. Such failures
  were previously ignored without a trace.
- `with_ttl` and `with_timeout` on every HTTP provider config, setting the
  TTL of the TXT records `present` creates and the timeout of each API
  request, as `Rfc2136Config` already allowed. `with_ttl` refuses a TTL
  outside the range the provider's API documents (Cloudflare, deSEC,
  DigitalOcean, Gandi, Hetzner, Infomaniak).

## [0.1.0] - 2026-10-20

First release.

### Added

- `Dns01Solver`, driving an `instant-acme` order through DNS-01 to a
  certificate: records are all placed, then polled on every authoritative
  nameserver of the zone, before the CA is asked to validate.
- `TlsAlpn01Solver`, building RFC 8737 challenge certificates and presenting
  them through a pluggable `ChallengeResponder`.
- DNS providers: Bunny DNS, Cloudflare, deSEC, DigitalOcean, Gandi, Google
  Cloud DNS, Hetzner, Infomaniak, OVH, Porkbun, PowerDNS, RFC 2136 (TSIG),
  Route53 and Scaleway. Any other backend can implement `DnsProvider`.
- Challenge material is removed on success, on error, and when the solve
  future is dropped before completing.
- HTTP providers retry throttled (429) and unavailable (503) requests,
  honouring `Retry-After`.
- `AccountStore` and `FileAccountStore` to persist ACME account credentials.
- Renewal helpers (`needs_renewal*`, `cert_lifetime`) reading a leaf
  certificate's validity.
- `testing` feature exposing `MockDnsProvider` and `MockChallengeResponder`.
- Minimum supported Rust version: 1.89.

[Unreleased]: https://github.com/kemeter/cheti/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/kemeter/cheti/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kemeter/cheti/releases/tag/v0.1.0

# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

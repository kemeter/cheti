//! Cheti — ACME DNS-01 challenge library with pluggable DNS providers.
//!
//! See [the README](https://github.com/kemeter/cheti) for usage examples.
#![doc = include_str!("../README.md")]

pub mod account_store;
pub mod dns;
pub mod error;
pub mod provider;
pub mod providers;
pub mod renewal;
pub mod solver;

pub use account_store::{AccountStore, FileAccountStore};
pub use dns::{find_zone, wait_for_propagation, DEFAULT_RESOLVERS};
pub use error::DnsError;
pub use provider::{DnsProvider, PropagationTiming};
pub use providers::cloudflare::{CloudflareConfig, CloudflareProvider};
pub use providers::gandi::{GandiConfig, GandiProvider};
pub use providers::ovh::{OvhConfig, OvhProvider};
pub use providers::scaleway::{ScalewayConfig, ScalewayProvider};
pub use renewal::{needs_renewal, needs_renewal_at};
pub use solver::Dns01Solver;

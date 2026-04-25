//! Cheti — ACME DNS-01 challenge library with pluggable DNS providers.

pub mod dns;
pub mod error;
pub mod provider;
pub mod providers;

pub use dns::{find_zone, wait_for_propagation, DEFAULT_RESOLVERS};
pub use error::DnsError;
pub use provider::{DnsProvider, PropagationTiming};
pub use providers::gandi::{GandiConfig, GandiProvider};
pub use providers::scaleway::{ScalewayConfig, ScalewayProvider};

use thiserror::Error;

/// Errors returned by the DNS provider layer.
///
/// Some variants may contain provider-supplied strings (API responses,
/// resolver messages). Callers should not log these verbatim to
/// user-facing output without redaction, as they may occasionally include
/// sensitive context returned by the upstream API.
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("zone not found for {0}")]
    ZoneNotFound(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("propagation timeout after {timeout_secs}s for {fqdn}")]
    PropagationTimeout { fqdn: String, timeout_secs: u64 },

    #[error("missing credentials: {0}")]
    MissingCredentials(String),

    #[error("resolver error: {0}")]
    Resolver(String),

    #[error("other: {0}")]
    Other(String),
}

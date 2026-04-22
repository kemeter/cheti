use thiserror::Error;

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

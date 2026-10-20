use thiserror::Error;

/// Errors returned by the DNS provider layer.
///
/// Some variants may contain provider-supplied strings (API responses,
/// resolver messages). Callers should not log these verbatim to
/// user-facing output without redaction, as they may occasionally include
/// sensitive context returned by the upstream API.
#[derive(Debug, Error)]
pub enum DnsError {
    /// The provider rejected the credentials, or lacks permission.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// No zone owning the name could be found.
    #[error("zone not found for {0}")]
    ZoneNotFound(String),

    /// The provider API answered with an error.
    #[error("API error: {0}")]
    Api(String),

    /// The HTTP request failed (connection, timeout, invalid response).
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// The TXT record did not become visible in time.
    #[error("propagation timeout after {timeout_secs}s for {fqdn}")]
    PropagationTimeout {
        /// The name that was polled.
        fqdn: String,
        /// The timeout that elapsed, in seconds.
        timeout_secs: u64,
    },

    /// A required credential (usually an environment variable) is missing.
    #[error("missing credentials: {0}")]
    MissingCredentials(String),

    /// A DNS lookup or resolver setup failed.
    #[error("resolver error: {0}")]
    Resolver(String),

    /// The ACME server or client returned an error.
    #[error("ACME error: {0}")]
    Acme(String),

    /// The ACME server offered no DNS-01 challenge for this identifier.
    #[error("no DNS-01 challenge offered for {0}")]
    NoDns01Challenge(String),

    /// The order ended in a status other than `Ready`.
    #[error("ACME order is {0}, expected Ready")]
    UnexpectedOrderStatus(String),

    /// An authorization is in a state that cannot be validated (e.g. invalid).
    #[error("ACME challenge invalid for {0}")]
    ChallengeInvalid(String),

    /// The account store could not read or write credentials.
    #[error("account store error: {0}")]
    Storage(String),

    /// A certificate could not be parsed.
    #[error("certificate parse error: {0}")]
    CertParse(String),

    /// Any other failure, such as invalid input.
    #[error("other: {0}")]
    Other(String),
}

impl From<instant_acme::Error> for DnsError {
    fn from(e: instant_acme::Error) -> Self {
        DnsError::Acme(e.to_string())
    }
}

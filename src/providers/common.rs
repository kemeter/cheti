use percent_encoding::{utf8_percent_encode, AsciiSet, PercentEncode, CONTROLS};
use url::Url;

use crate::error::DnsError;

const MAX_ERROR_BODY: usize = 512;

const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub(crate) fn encode_path(segment: &str) -> PercentEncode<'_> {
    utf8_percent_encode(segment, PATH_SEGMENT)
}

pub(crate) fn validate_fqdn(fqdn: &str) -> Result<(), DnsError> {
    let trimmed = fqdn.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(DnsError::Other(format!("invalid fqdn length: {fqdn}")));
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::Other(format!("invalid label in {fqdn}")));
        }
        if label.contains('\0') {
            return Err(DnsError::Other("fqdn contains null byte".into()));
        }
    }
    Ok(())
}

pub(crate) fn relative_name(fqdn: &str, zone: &str) -> String {
    let fqdn = fqdn.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if fqdn == zone {
        return "@".to_string();
    }
    let suffix = format!(".{zone}");
    fqdn.strip_suffix(&suffix).unwrap_or(fqdn).to_string()
}

pub(crate) fn validate_https_base(base: &str, provider: &str) -> Result<(), DnsError> {
    let parsed = Url::parse(base).map_err(|_| {
        DnsError::Other(format!("{provider} api_base is not a valid URL: {base}"))
    })?;
    let scheme_ok = parsed.scheme() == "https"
        || (parsed.scheme() == "http"
            && matches!(
                parsed.host_str(),
                Some("localhost") | Some("127.0.0.1") | Some("::1")
            ));
    if !scheme_ok {
        return Err(DnsError::Other(format!(
            "{provider} api_base must use https:// (got {base})"
        )));
    }
    Ok(())
}

pub(crate) async fn api_error(
    provider: &str,
    method: &str,
    path: String,
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> DnsError {
    let raw = response.text().await.unwrap_or_default();
    let text = if raw.len() > MAX_ERROR_BODY {
        let mut cut = MAX_ERROR_BODY;
        while cut > 0 && !raw.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut truncated = raw[..cut].to_string();
        truncated.push_str("…(truncated)");
        truncated
    } else {
        raw
    };
    DnsError::Api(format!(
        "{provider} {method} {path} returned {status}: {text}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_name_strips_zone_suffix() {
        assert_eq!(
            relative_name("_acme-challenge.kemeter.app", "kemeter.app"),
            "_acme-challenge"
        );
    }

    #[test]
    fn relative_name_handles_nested_subdomain() {
        assert_eq!(
            relative_name("_acme-challenge.api.kemeter.app", "kemeter.app"),
            "_acme-challenge.api"
        );
    }

    #[test]
    fn relative_name_returns_at_for_apex() {
        assert_eq!(relative_name("kemeter.app", "kemeter.app"), "@");
    }

    #[test]
    fn relative_name_ignores_trailing_dot() {
        assert_eq!(
            relative_name("_acme-challenge.kemeter.app.", "kemeter.app."),
            "_acme-challenge"
        );
    }

    #[test]
    fn validate_fqdn_accepts_normal() {
        assert!(validate_fqdn("_acme-challenge.kemeter.app").is_ok());
        assert!(validate_fqdn("kemeter.app.").is_ok());
    }

    #[test]
    fn validate_fqdn_rejects_empty() {
        assert!(validate_fqdn("").is_err());
        assert!(validate_fqdn(".").is_err());
    }

    #[test]
    fn validate_fqdn_rejects_double_dot() {
        assert!(validate_fqdn("foo..bar.com").is_err());
    }

    #[test]
    fn validate_fqdn_rejects_oversize_label() {
        let long = "a".repeat(64);
        let fqdn = format!("{long}.com");
        assert!(validate_fqdn(&fqdn).is_err());
    }

    #[test]
    fn validate_fqdn_rejects_null_byte() {
        assert!(validate_fqdn("foo\0.bar.com").is_err());
    }

    #[test]
    fn validate_https_base_rejects_http() {
        assert!(validate_https_base("http://evil.example", "test").is_err());
    }

    #[test]
    fn validate_https_base_accepts_https() {
        assert!(validate_https_base("https://api.example.com", "test").is_ok());
    }

    #[test]
    fn validate_https_base_accepts_localhost_for_tests() {
        assert!(validate_https_base("http://localhost:8080", "test").is_ok());
    }

    #[test]
    fn validate_https_base_rejects_localhost_lookalike() {
        assert!(validate_https_base("http://localhost.evil.com", "test").is_err());
    }

    #[test]
    fn validate_https_base_rejects_userinfo_smuggling() {
        assert!(validate_https_base("http://localhost@attacker.com", "test").is_err());
    }

    #[test]
    fn encode_path_escapes_slash() {
        let s = encode_path("foo/../bar").to_string();
        assert_eq!(s, "foo%2F..%2Fbar");
    }
}

mod common;

/// The Bunny DNS DNS provider.
pub mod bunny;
/// The Cloudflare DNS provider.
pub mod cloudflare;
/// The deSEC DNS provider.
pub mod desec;
/// The DigitalOcean DNS provider.
pub mod digitalocean;
/// The Gandi DNS provider.
pub mod gandi;
/// The Google Cloud DNS DNS provider.
pub mod google_cloud_dns;
/// The Hetzner DNS provider.
pub mod hetzner;
/// The Infomaniak DNS provider.
pub mod infomaniak;
/// The OVH DNS provider.
pub mod ovh;
/// The Porkbun DNS provider.
pub mod porkbun;
/// The PowerDNS DNS provider.
pub mod powerdns;
/// The RFC 2136 (dynamic DNS update) provider.
pub mod rfc2136;
/// The Route53 DNS provider.
pub mod route53;
/// The Scaleway DNS provider.
pub mod scaleway;

use crate::error::DnsError;
use crate::provider::DnsProvider;

/// The names [`from_env`] takes, one per provider. lego's names for them
/// (`gandiv5`, `pdns`, `gcloud`) are taken too.
pub const NAMES: &[&str] = &[
    "bunny",
    "cloudflare",
    "desec",
    "digitalocean",
    "gandi",
    "google_cloud_dns",
    "hetzner",
    "infomaniak",
    "ovh",
    "porkbun",
    "powerdns",
    "rfc2136",
    "route53",
    "scaleway",
];

/// The provider named `name`, built from its environment variables, as its
/// own `from_env` builds it: the way to pick a provider from configuration,
/// as Traefik and lego do with a provider name alone.
///
/// `name` is one of [`NAMES`], or lego's name for the same provider
/// (`gandiv5`, `pdns`, `gcloud`), compared without case. Each provider reads
/// cheti's variable names and lego's where they differ, and each variable
/// may be read from the file its `<NAME>_FILE` variable names instead, as
/// Docker and Kubernetes secrets are mounted.
pub fn from_env(name: &str) -> Result<Box<dyn DnsProvider>, DnsError> {
    build(name, &common::process_env)
}

/// [`from_env`], each variable read through `lookup` rather than from the
/// process's environment: to take a variable under another name (a second
/// account's token), or a value from configuration.
///
/// ```
/// // The token of a second Cloudflare account, under a name of its own.
/// let provider = cheti::providers::from_env_with("cloudflare", |var| match var {
///     "CLOUDFLARE_API_TOKEN" => std::env::var("CF_TOKEN_ACCOUNT_B").ok(),
///     other => std::env::var(other).ok(),
/// });
/// # let _ = provider;
/// ```
pub fn from_env_with(
    name: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Box<dyn DnsProvider>, DnsError> {
    build(name, &lookup)
}

fn build(name: &str, lookup: common::Lookup<'_>) -> Result<Box<dyn DnsProvider>, DnsError> {
    let provider: Box<dyn DnsProvider> = match name.to_ascii_lowercase().as_str() {
        "bunny" => Box::new(bunny::BunnyProvider::from_lookup(lookup)?),
        "cloudflare" => Box::new(cloudflare::CloudflareProvider::from_lookup(lookup)?),
        "desec" => Box::new(desec::DesecProvider::from_lookup(lookup)?),
        "digitalocean" => Box::new(digitalocean::DigitalOceanProvider::from_lookup(lookup)?),
        "gandi" | "gandiv5" => Box::new(gandi::GandiProvider::from_lookup(lookup)?),
        "google_cloud_dns" | "gcloud" => Box::new(
            google_cloud_dns::GoogleCloudDnsProvider::from_lookup(lookup)?,
        ),
        "hetzner" => Box::new(hetzner::HetznerProvider::from_lookup(lookup)?),
        "infomaniak" => Box::new(infomaniak::InfomaniakProvider::from_lookup(lookup)?),
        "ovh" => Box::new(ovh::OvhProvider::from_lookup(lookup)?),
        "porkbun" => Box::new(porkbun::PorkbunProvider::from_lookup(lookup)?),
        "powerdns" | "pdns" => Box::new(powerdns::PowerDnsProvider::from_lookup(lookup)?),
        "rfc2136" => Box::new(rfc2136::Rfc2136Provider::from_lookup(lookup)?),
        "route53" => Box::new(route53::Route53Provider::from_lookup(lookup)?),
        "scaleway" => Box::new(scaleway::ScalewayProvider::from_lookup(lookup)?),
        _ => {
            return Err(DnsError::Other(format!(
                "unknown DNS provider `{name}`: expected one of {}",
                NAMES.join(", ")
            )))
        }
    };
    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The tests here set environment variables: one at a time.
    static ENV: Mutex<()> = Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn a_variable_is_read_from_itself_or_its_file() {
        let _env = lock();
        std::env::set_var("CHETI_TEST_DIRECT", "direct");
        assert_eq!(
            common::env_value(&common::process_env, &["CHETI_TEST_DIRECT"])
                .unwrap()
                .as_deref(),
            Some("direct")
        );

        let dir = std::env::temp_dir().join(format!("cheti-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret");
        std::fs::write(&file, "from-file\n").unwrap();
        std::env::set_var("CHETI_TEST_SECRET_FILE", &file);
        assert_eq!(
            common::env_value(&common::process_env, &["CHETI_TEST_SECRET"])
                .unwrap()
                .as_deref(),
            Some("from-file")
        );
        std::env::remove_var("CHETI_TEST_SECRET_FILE");
        std::fs::remove_dir_all(&dir).unwrap();
        std::env::remove_var("CHETI_TEST_DIRECT");
    }

    /// The first name set wins; an empty one counts as unset.
    #[test]
    fn the_first_name_set_wins() {
        let _env = lock();
        std::env::set_var("CHETI_TEST_FIRST", "");
        std::env::set_var("CHETI_TEST_SECOND", "second");
        assert_eq!(
            common::env_value(
                &common::process_env,
                &["CHETI_TEST_FIRST", "CHETI_TEST_SECOND"]
            )
            .unwrap()
            .as_deref(),
            Some("second")
        );
        std::env::remove_var("CHETI_TEST_FIRST");
        std::env::remove_var("CHETI_TEST_SECOND");
    }

    #[test]
    fn a_missing_variable_names_every_accepted_one() {
        let _env = lock();
        let err = common::env_required(
            &common::process_env,
            &["CHETI_TEST_NONE", "CHETI_TEST_ALIAS"],
        )
        .unwrap_err();
        let message = err.to_string();
        for name in [
            "CHETI_TEST_NONE",
            "CHETI_TEST_NONE_FILE",
            "CHETI_TEST_ALIAS",
            "CHETI_TEST_ALIAS_FILE",
        ] {
            assert!(message.contains(name), "{message}");
        }
    }

    #[test]
    fn an_unreadable_file_is_an_error() {
        let _env = lock();
        std::env::set_var("CHETI_TEST_GONE_FILE", "/nonexistent/cheti/secret");
        assert!(common::env_value(&common::process_env, &["CHETI_TEST_GONE"]).is_err());
        std::env::remove_var("CHETI_TEST_GONE_FILE");
    }

    /// A provider is built by its name or lego's, from cheti's variables or
    /// lego's.
    #[test]
    fn a_provider_is_built_by_name_from_lego_variables() {
        let _env = lock();
        std::env::set_var("CF_DNS_API_TOKEN", "lego-token");
        assert!(from_env("cloudflare").is_ok());
        assert!(from_env("Cloudflare").is_ok());
        std::env::remove_var("CF_DNS_API_TOKEN");

        std::env::set_var("PDNS_API_URL", "https://pdns.example.com");
        std::env::set_var("PDNS_API_KEY", "key");
        assert!(from_env("pdns").is_ok());
        assert!(from_env("powerdns").is_ok());
        std::env::remove_var("PDNS_API_URL");
        std::env::remove_var("PDNS_API_KEY");
    }

    /// Through a lookup, a variable can come under another name, without
    /// touching the process's environment.
    #[test]
    fn a_provider_is_built_through_a_lookup() {
        let lookup = |var: &str| match var {
            "OVH_APPLICATION_KEY" => Some("ak".to_string()),
            "OVH_APPLICATION_SECRET" => Some("as".to_string()),
            "OVH_CONSUMER_KEY" => Some("ck".to_string()),
            "OVH_ENDPOINT" => Some("ovh-ca".to_string()),
            _ => None,
        };
        assert!(from_env_with("ovh", lookup).is_ok());
        let missing = from_env_with("ovh", |_| None).err().unwrap().to_string();
        assert!(missing.contains("OVH_APPLICATION_KEY"), "{missing}");
        let bad_endpoint = from_env_with("ovh", |var| match var {
            "OVH_ENDPOINT" => Some("ovh-asia".to_string()),
            other => lookup(other),
        });
        assert!(bad_endpoint.is_err());
    }

    #[test]
    fn an_unknown_name_lists_the_known_ones() {
        let _env = lock();
        let message = from_env("azure").err().unwrap().to_string();
        assert!(
            message.contains("unknown DNS provider `azure`"),
            "{message}"
        );
        assert!(message.contains("route53"), "{message}");
    }

    #[test]
    fn every_name_is_known() {
        let _env = lock();
        for name in NAMES {
            // Without credentials: told missing, not unknown.
            let message = match from_env(name) {
                Ok(_) => continue,
                Err(e) => e.to_string(),
            };
            assert!(
                !message.contains("unknown DNS provider"),
                "{name}: {message}"
            );
        }
    }

    #[test]
    fn ovh_endpoints_are_named_as_in_lego() {
        for endpoint in [
            "ovh-eu",
            "ovh-ca",
            "ovh-us",
            "kimsufi-eu",
            "kimsufi-ca",
            "soyoustart-eu",
            "soyoustart-ca",
        ] {
            assert!(ovh::OvhConfig::new("a", "b", "c")
                .with_endpoint(endpoint)
                .is_ok());
        }
        assert!(ovh::OvhConfig::new("a", "b", "c")
            .with_endpoint("ovh-asia")
            .is_err());
    }
}

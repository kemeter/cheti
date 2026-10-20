//! Issue a certificate through DNS-01 with Cloudflare.
//!
//! ```sh
//! CLOUDFLARE_API_TOKEN=... cargo run --example issue_certificate -- \
//!     admin@example.com example.com '*.example.com'
//! ```
//!
//! Uses Let's Encrypt staging unless `ACME_DIRECTORY` says otherwise. The
//! ACME account is kept in `account.json` (override with `ACME_ACCOUNT`), and
//! the certificate chain and key are written to `cert.pem` and `key.pem`.

use cheti::{AccountStore, CloudflareProvider, Dns01Solver, FileAccountStore};
use instant_acme::{Account, Identifier, NewAccount, NewOrder};

const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let contact = args
        .next()
        .ok_or("usage: issue_certificate <contact-email> <domain>...")?;
    let domains: Vec<String> = args.collect();
    if domains.is_empty() {
        return Err("at least one domain is required".into());
    }

    let directory = std::env::var("ACME_DIRECTORY").unwrap_or_else(|_| LE_STAGING.to_string());
    let store = FileAccountStore::new(
        std::env::var("ACME_ACCOUNT").unwrap_or_else(|_| "account.json".to_string()),
    );

    // Reuse the stored account, so each run does not create a new one.
    let account = match store.load()? {
        Some(credentials) => Account::builder()?.from_credentials(credentials).await?,
        None => {
            let contact = format!("mailto:{contact}");
            let (account, credentials) = Account::builder()?
                .create(
                    &NewAccount {
                        contact: &[&contact],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    directory,
                    None,
                )
                .await?;
            store.save(&credentials)?;
            account
        }
    };

    let identifiers: Vec<Identifier> = domains.into_iter().map(Identifier::Dns).collect();
    let order = account.new_order(&NewOrder::new(&identifiers)).await?;

    let solver = Dns01Solver::new(CloudflareProvider::from_env()?);
    let (cert_chain_pem, key_pem) = solver.solve_and_finalize(order).await?;

    std::fs::write("cert.pem", cert_chain_pem)?;
    std::fs::write("key.pem", key_pem)?;
    println!("wrote cert.pem and key.pem");
    Ok(())
}

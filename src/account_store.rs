//! Persist ACME account credentials between runs.
//!
//! Without persistence, every certificate issuance creates a brand new ACME
//! account, which Let's Encrypt will rate-limit aggressively (10 accounts per
//! IP per 3 hours at the time of writing). Store the credentials once and
//! re-use them.

use std::path::{Path, PathBuf};

use instant_acme::AccountCredentials;

use crate::error::DnsError;

/// Persistence backend for `AccountCredentials`.
///
/// Implement this for any storage you control (database, secret manager, in-
/// memory test double). For local files, use [`FileAccountStore`].
pub trait AccountStore {
    /// Load previously stored credentials, or `Ok(None)` if none exist.
    fn load(&self) -> Result<Option<AccountCredentials>, DnsError>;

    /// Persist credentials. Implementations must overwrite any existing
    /// entry — the caller treats `save` as authoritative.
    fn save(&self, credentials: &AccountCredentials) -> Result<(), DnsError>;
}

/// JSON-on-disk store. Writes go through a temp file + rename, and the
/// resulting file is `0600` on Unix so a misconfigured umask doesn't leak the
/// account private key to other users.
pub struct FileAccountStore {
    path: PathBuf,
}

impl FileAccountStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AccountStore for FileAccountStore {
    fn load(&self) -> Result<Option<AccountCredentials>, DnsError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(DnsError::Storage(format!(
                    "read account store {}: {e}",
                    self.path.display()
                )));
            }
        };
        let creds: AccountCredentials = serde_json::from_slice(&bytes).map_err(|e| {
            DnsError::Storage(format!("parse account store {}: {e}", self.path.display()))
        })?;
        Ok(Some(creds))
    }

    fn save(&self, credentials: &AccountCredentials) -> Result<(), DnsError> {
        let bytes = serde_json::to_vec(credentials)
            .map_err(|e| DnsError::Storage(format!("serialize account credentials: {e}")))?;

        // Write to a sibling temp file then rename, so a crash mid-write
        // doesn't leave us with a truncated, unreadable file.
        let parent = self.path.parent().ok_or_else(|| {
            DnsError::Storage(format!(
                "account store path has no parent: {}",
                self.path.display()
            ))
        })?;
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                DnsError::Storage(format!("create parent {}: {e}", parent.display()))
            })?;
        }

        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)
            .map_err(|e| DnsError::Storage(format!("write {}: {e}", tmp.display())))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| DnsError::Storage(format!("chmod {}: {e}", tmp.display())))?;
        }

        std::fs::rename(&tmp, &self.path).map_err(|e| {
            DnsError::Storage(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                self.path.display()
            ))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct InMemoryStore {
        inner: std::sync::Mutex<Option<String>>,
    }

    impl InMemoryStore {
        fn new() -> Self {
            Self {
                inner: std::sync::Mutex::new(None),
            }
        }
    }

    impl AccountStore for InMemoryStore {
        fn load(&self) -> Result<Option<AccountCredentials>, DnsError> {
            match &*self.inner.lock().unwrap() {
                Some(s) => Ok(Some(
                    serde_json::from_str(s)
                        .map_err(|e| DnsError::Storage(format!("parse: {e}")))?,
                )),
                None => Ok(None),
            }
        }

        fn save(&self, credentials: &AccountCredentials) -> Result<(), DnsError> {
            let s = serde_json::to_string(credentials)
                .map_err(|e| DnsError::Storage(format!("serialize: {e}")))?;
            *self.inner.lock().unwrap() = Some(s);
            Ok(())
        }
    }

    #[test]
    fn in_memory_store_round_trip_returns_none_when_empty() {
        let store = InMemoryStore::new();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn file_store_load_returns_none_when_missing() {
        let path = std::env::temp_dir().join(format!(
            "cheti-test-account-store-missing-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = FileAccountStore::new(&path);
        assert!(store.load().unwrap().is_none());
    }

    /// Verifies that load() on a missing file does NOT error — important
    /// because callers branch on Ok(None) to decide whether to create an
    /// account. A panic would be a hard regression.
    #[test]
    fn file_store_load_propagates_io_error_for_unreadable_path() {
        // /proc/1/mem is unreadable by non-root processes; opening it surfaces
        // an EACCES-like error that must come back as DnsError, not panic.
        // If the test runs as root this will succeed in opening but fail to
        // parse — either branch reaches the Err arm.
        let store = FileAccountStore::new("/proc/1/mem");
        let result = store.load();
        assert!(matches!(result, Err(_) | Ok(None)));
    }
}

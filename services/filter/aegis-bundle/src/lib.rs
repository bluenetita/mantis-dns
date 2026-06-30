//! Generated bundle types + signature verification.
//! This crate is the Rust half of the cross-language contract defined in proto/bundle.proto.

pub mod gen {
    include!(concat!(env!("OUT_DIR"), "/aegis.bundle.v1.rs"));
}

pub use gen::{Action, Bundle, CategorySet, FailurePolicy};

use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use prost::Message;

#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("signature missing")]
    MissingSignature,
    #[error("signature invalid")]
    InvalidSignature,
}

/// Verifies a bundle's ed25519 signature. The signature is computed over the
/// serialized message with `signature` zeroed, so we clear it before re-encoding.
pub fn verify(bundle: &Bundle, public_key: &VerifyingKey) -> Result<()> {
    if bundle.signature.len() != 64 {
        bail!(VerifyError::MissingSignature);
    }
    let sig = Signature::from_slice(&bundle.signature)?;

    let mut unsigned = bundle.clone();
    unsigned.signature.clear();
    let bytes = unsigned.encode_to_vec();

    public_key
        .verify(&bytes, &sig)
        .map_err(|_| VerifyError::InvalidSignature)?;
    Ok(())
}

/// Holds the currently-active bundle behind an atomic pointer swap so the hot
/// read path (DNS resolution) never blocks on a writer publishing a new
/// bundle. Readers always see either the old or the new bundle, never a torn
/// state.
pub struct BundleStore {
    current: arc_swap::ArcSwapOption<Bundle>,
}

impl BundleStore {
    pub fn empty() -> Self {
        Self {
            current: arc_swap::ArcSwapOption::const_empty(),
        }
    }

    /// Verifies `bundle` and, if valid, atomically publishes it as current.
    /// Rejects (and leaves the old bundle in place) if verification fails or
    /// if `bundle` is not newer than what's already loaded.
    pub fn try_publish(&self, bundle: Bundle, public_key: &VerifyingKey) -> Result<()> {
        verify(&bundle, public_key)?;

        if let Some(existing) = self.current.load().as_ref() {
            if bundle.version <= existing.version {
                bail!(
                    "refusing to publish stale bundle: incoming version {} <= current {}",
                    bundle.version,
                    existing.version
                );
            }
        }

        self.current.store(Some(std::sync::Arc::new(bundle)));
        Ok(())
    }

    /// Lock-free read of the current bundle, if any has been published yet.
    pub fn current(&self) -> Option<std::sync::Arc<Bundle>> {
        self.current.load_full()
    }
}

impl Default for BundleStore {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn signed(version: u64, signing_key: &SigningKey) -> Bundle {
        let mut bundle = Bundle {
            tenant_id: "t".into(),
            group_id: "g".into(),
            version,
            ..Default::default()
        };
        let bytes = bundle.encode_to_vec();
        let sig = ed25519_dalek::Signer::sign(signing_key, &bytes);
        bundle.signature = sig.to_bytes().to_vec();
        bundle
    }

    #[test]
    fn rejects_stale_version() {
        // Fixed test seed bytes — deterministic, fine for a unit test signing key.
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key = signing_key.verifying_key();

        let store = BundleStore::empty();
        store.try_publish(signed(2, &signing_key), &public_key).unwrap();
        assert!(store.current().unwrap().version == 2);

        let err = store.try_publish(signed(1, &signing_key), &public_key);
        assert!(err.is_err());
        assert!(store.current().unwrap().version == 2, "stale publish must not overwrite");
    }

    #[test]
    fn empty_store_has_no_current() {
        let store = BundleStore::empty();
        assert!(store.current().is_none());
    }
}

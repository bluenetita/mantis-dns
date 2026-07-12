/*
 * Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Generated bundle types + signature verification.
//! This crate is the Rust half of the cross-language contract defined in proto/bundle.proto.

pub mod gen {
    include!(concat!(env!("OUT_DIR"), "/mantis.bundle.v1.rs"));
}

pub use gen::{Action, BlockMode, BlockResponse, Bundle, CategorySet, FailurePolicy};

use anyhow::{bail, Result};
use ed25519_dalek::{Signature, VerifyingKey};
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
///
/// Uses `verify_strict` (not the permissive `verify`) for the same reason
/// `upstream_bundle.rs::fetch_upstream_bundle` does: `verify` accepts
/// non-canonical/cofactored signature encodings, which drops the SUF-CMA
/// (strong unforgeability) guarantee — a single message could have more than
/// one valid signature. Not exploitable into a bypass with today's single
/// pinned key, but there's no reason to accept the weaker guarantee here
/// when the sibling verification path already doesn't.
pub fn verify(bundle: &Bundle, public_key: &VerifyingKey) -> Result<()> {
    if bundle.signature.len() != 64 {
        bail!(VerifyError::MissingSignature);
    }
    let sig = Signature::from_slice(&bundle.signature)?;

    let mut unsigned = bundle.clone();
    unsigned.signature.clear();
    let bytes = unsigned.encode_to_vec();

    public_key
        .verify_strict(&bytes, &sig)
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
    ///
    /// The version check and the publish are one atomic `rcu` operation, not
    /// a separate load-then-store — a plain load-check-store here would let
    /// two racing publishers each pass the check against the same stale
    /// snapshot, so a lower-version bundle whose store happens to land second
    /// could silently overwrite a higher-version one that already published.
    pub fn try_publish(&self, bundle: Bundle, public_key: &VerifyingKey) -> Result<()> {
        verify(&bundle, public_key)?;

        let bundle = std::sync::Arc::new(bundle);
        let incoming_version = bundle.version;

        // rcu's closure may re-run under contention, but only the winning
        // attempt's return value is ever stored — see `Self::current`'s doc.
        // When rejecting, returning `existing.clone()` unchanged makes the
        // "swap" a no-op (same Arc pointer), not an actual replacement.
        let prev = self.current.rcu(|existing| match existing {
            Some(current) if incoming_version <= current.version => existing.clone(),
            _ => Some(std::sync::Arc::clone(&bundle)),
        });

        if let Some(prev) = prev {
            if incoming_version <= prev.version {
                bail!(
                    "refusing to publish stale bundle: incoming version {} <= current {}",
                    incoming_version,
                    prev.version
                );
            }
        }
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

    #[test]
    fn concurrent_publishes_never_regress_the_version() {
        // Many threads race to publish distinct versions against the same
        // (initially empty) store, released together via a Barrier to
        // maximize contention on the very first publish — the case a plain
        // load-then-store handles incorrectly, since every thread's initial
        // load sees an empty store and none of them would see each other's
        // writes without the atomic retry `rcu` provides.
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let public_key = signing_key.verifying_key();
        let store = std::sync::Arc::new(BundleStore::empty());

        const N: u64 = 64;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N as usize));
        let handles: Vec<_> = (1..=N)
            .map(|version| {
                let store = std::sync::Arc::clone(&store);
                let barrier = std::sync::Arc::clone(&barrier);
                let bundle = signed(version, &signing_key);
                std::thread::spawn(move || {
                    barrier.wait();
                    // A publish can legitimately fail if another thread's
                    // higher version already won — only assert on success.
                    let _ = store.try_publish(bundle, &public_key);
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        // Whatever interleaving occurred, the highest version submitted must
        // be what's live at the end — a lower version can never have won a
        // race against a higher one that also published.
        assert_eq!(store.current().unwrap().version, N);
    }
}

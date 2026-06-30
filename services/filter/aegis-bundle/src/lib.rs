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

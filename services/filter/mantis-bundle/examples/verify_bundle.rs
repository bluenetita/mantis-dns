//! Sprint 1 exit-criteria check: load a bundle + pubkey produced by
//! services/control/mantis_control/compiler/build_empty_bundle.py and verify it.
//!
//! Run from services/control: python -m mantis_control.compiler.build_empty_bundle
//! Then from repo root: cargo run -p mantis-bundle --example verify_bundle -- services/control/bundle.bin services/control/bundle_pubkey.bin

use mantis_bundle::{verify, Bundle};
use ed25519_dalek::VerifyingKey;
use prost::Message;
use std::env;
use std::fs;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        anyhow::bail!("usage: verify_bundle <bundle.bin> <pubkey.bin>");
    }

    let bundle_bytes = fs::read(&args[1])?;
    let pubkey_bytes = fs::read(&args[2])?;

    let bundle = Bundle::decode(bundle_bytes.as_slice())?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .expect("pubkey must be 32 bytes");
    let public_key = VerifyingKey::from_bytes(&pubkey_array)?;

    verify(&bundle, &public_key)?;

    println!(
        "OK: bundle verified. tenant={} group={} version={} signer={}",
        bundle.tenant_id, bundle.group_id, bundle.version, bundle.signer_key_id
    );
    Ok(())
}

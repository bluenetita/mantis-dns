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

//! Certificate-pinning `ServerCertVerifier` for upstream DoT/DoH resolvers
//! configured with `tls_pin_sha256` (design.md §21.2).
//!
//! Before this existed, `ResolverConfig_` didn't even deserialize the
//! `tls_pin_sha256` field the control plane ships in the upstream bundle —
//! an admin who configured a pin got ordinary WebPKI CA-trust verification
//! instead, with the pin silently ignored end to end.
//!
//! This verifier skips normal chain-of-trust validation entirely and
//! instead accepts only a leaf certificate whose SHA-256 digest matches one
//! of the configured pins — the classic HPKP-style model, appropriate here
//! since configuring a pin means naming one specific certificate to trust
//! (often self-signed or private-CA, for an operator's own DoT/DoH
//! infrastructure), not "also require a public CA signature". The TLS
//! handshake signature is still cryptographically verified against the
//! pinned certificate's public key (via rustls's own WebPKI
//! signature-verification helpers), so an attacker who merely replays the
//! pinned certificate's bytes without holding its private key is still
//! rejected — pinning only widens *which* certificate is trusted, not
//! whether the handshake has to be genuine.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};

pub struct PinnedCertVerifier {
    pins: Vec<[u8; 32]>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedCertVerifier")
            .field("pin_count", &self.pins.len())
            .finish()
    }
}

impl PinnedCertVerifier {
    pub fn new(pins: Vec<[u8; 32]>, provider: Arc<CryptoProvider>) -> Self {
        Self { pins, provider }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self.pins.contains(&digest) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "presented certificate (sha256:{}) does not match any pinned hash",
                hex::encode(digest)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Parses a `tls_pin_sha256` entry into a raw 32-byte digest. Accepts the
/// same `"sha256:<hex>"` / bare-hex / colon-separated forms as
/// `MANTIS_CONTROL_PUBLIC_KEY_SHA256` (see `normalize_sha256_pin` in
/// lib.rs) for a consistent admin-facing format across both pinning
/// features. Returns `None` (logged by the caller) rather than erroring the
/// whole resolver build on one malformed entry.
pub fn parse_pin(pin: &str) -> Option<[u8; 32]> {
    let normalized = crate::normalize_sha256_pin(pin);
    if normalized.len() != 64 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(normalized).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pin_accepts_bare_hex() {
        let hex = "a".repeat(64);
        assert_eq!(parse_pin(&hex), Some([0xaa; 32]));
    }

    #[test]
    fn parse_pin_accepts_sha256_prefix_and_colons() {
        let hex = "bb".repeat(32);
        let piece = format!("sha256:{}", hex.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":"));
        assert_eq!(parse_pin(&piece), Some([0xbb; 32]));
    }

    #[test]
    fn parse_pin_rejects_wrong_length() {
        assert_eq!(parse_pin("abcd"), None);
    }

    #[test]
    fn parse_pin_rejects_non_hex() {
        assert_eq!(parse_pin(&"z".repeat(64)), None);
    }

    #[test]
    fn verifier_accepts_a_pinned_certificate_digest() {
        let cert_bytes = b"pretend-der-encoded-certificate";
        let digest: [u8; 32] = Sha256::digest(cert_bytes).into();
        let verifier = PinnedCertVerifier::new(
            vec![digest],
            Arc::new(hickory_proto::rustls::default_provider()),
        );

        let end_entity = CertificateDer::from(cert_bytes.to_vec());
        let server_name: ServerName<'static> = ServerName::try_from("example.test").unwrap();
        let result = verifier.verify_server_cert(&end_entity, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok());
    }

    #[test]
    fn verifier_rejects_a_non_pinned_certificate() {
        let pinned_bytes = b"the-cert-that-is-actually-pinned";
        let digest: [u8; 32] = Sha256::digest(pinned_bytes).into();
        let verifier = PinnedCertVerifier::new(
            vec![digest],
            Arc::new(hickory_proto::rustls::default_provider()),
        );

        let presented = CertificateDer::from(b"a-completely-different-certificate".to_vec());
        let server_name: ServerName<'static> = ServerName::try_from("example.test").unwrap();
        let result = verifier.verify_server_cert(&presented, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_err(), "a non-pinned certificate must be rejected");
    }
}

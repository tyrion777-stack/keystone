//! Public keys of every algorithm Keystone can verify.
//!
//! A key carries its algorithm in its own string, so it is never read as the wrong kind.
//!
//! Wire form (the `author` field of a `SignedMessage`), one spelling per key:
//! - Ed25519: bare hex of the 32-byte key, unchanged since v0.1 so existing verifiers keep working.
//! - P-256:   `p256:` + lowercase hex of the 33-byte compressed SEC1 point.
//!
//! Display form always carries the prefix: `ed25519:…` or `p256:…`.
//!
//! Signatures:
//! - Ed25519: 64 bytes.
//! - P-256:   ECDSA with SHA-256, 64 bytes `r || s`, low-S only so each message has one valid signature.

use std::fmt;

use ed25519_dalek::Verifier;

use crate::error::KeystoneError;

const P256_PREFIX: &str = "p256:";
const ED25519_PREFIX: &str = "ed25519:";
const P256_COMPRESSED_LEN: usize = 33;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    P256,
}

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "ed25519",
            Algorithm::P256 => "p256",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

impl PublicKey {
    /// Parse the wire form used in `SignedMessage::author`. Strict: an `ed25519:` prefix or an
    /// unknown prefix is rejected, so every key has exactly one wire spelling.
    pub fn from_wire(s: &str) -> Result<Self, KeystoneError> {
        if let Some(hex_str) = s.strip_prefix(P256_PREFIX) {
            return parse_p256(hex_str);
        }
        if let Some((alg, _)) = s.split_once(':') {
            return Err(KeystoneError::UnsupportedAlgorithm(alg.to_string()));
        }
        parse_ed25519(s)
    }

    /// Parse either the display form (`ed25519:…`, `p256:…`) or the wire form.
    /// Use this for keys typed or pasted by people; use `from_wire` for message authors.
    pub fn parse(s: &str) -> Result<Self, KeystoneError> {
        match s.strip_prefix(ED25519_PREFIX) {
            Some(hex_str) => parse_ed25519(hex_str),
            None => Self::from_wire(s),
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        match self {
            PublicKey::Ed25519(_) => Algorithm::Ed25519,
            PublicKey::P256(_) => Algorithm::P256,
        }
    }

    /// The form used in `SignedMessage::author`.
    pub fn to_wire(&self) -> String {
        match self {
            PublicKey::Ed25519(_) => self.hex(),
            PublicKey::P256(_) => format!("{P256_PREFIX}{}", self.hex()),
        }
    }

    fn hex(&self) -> String {
        match self {
            PublicKey::Ed25519(k) => hex::encode(k.to_bytes()),
            PublicKey::P256(k) => hex::encode(k.to_encoded_point(true).as_bytes()),
        }
    }

    /// Verify a hex-encoded signature over `message` with this key.
    pub fn verify(&self, message: &[u8], signature_hex: &str) -> Result<(), KeystoneError> {
        let sig_bytes = hex::decode(signature_hex)?;
        match self {
            PublicKey::Ed25519(key) => {
                let sig_arr: [u8; 64] = sig_bytes
                    .try_into()
                    .map_err(|_| KeystoneError::InvalidSignature)?;
                let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
                key.verify(message, &signature)
                    .map_err(|_| KeystoneError::InvalidSignature)
            }
            PublicKey::P256(key) => {
                let signature = p256::ecdsa::Signature::from_slice(&sig_bytes)
                    .map_err(|_| KeystoneError::InvalidSignature)?;
                // normalize_s returns Some only when s is in the high half: reject those.
                if signature.normalize_s().is_some() {
                    return Err(KeystoneError::InvalidSignature);
                }
                key.verify(message, &signature)
                    .map_err(|_| KeystoneError::InvalidSignature)
            }
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm().as_str(), self.hex())
    }
}

/// Ed25519 hex is parsed exactly as before Stage 1 (any letter case), so no existing
/// message stops verifying.
fn parse_ed25519(hex_str: &str) -> Result<PublicKey, KeystoneError> {
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| KeystoneError::InvalidPublicKey("ed25519 key must be 32 bytes".into()))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| KeystoneError::InvalidPublicKey(e.to_string()))?;
    Ok(PublicKey::Ed25519(key))
}

fn parse_p256(hex_str: &str) -> Result<PublicKey, KeystoneError> {
    if hex_str.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(KeystoneError::InvalidPublicKey(
            "p256 key must be lowercase hex".into(),
        ));
    }
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != P256_COMPRESSED_LEN || !matches!(bytes[0], 0x02 | 0x03) {
        return Err(KeystoneError::InvalidPublicKey(
            "p256 key must be a 33-byte compressed point".into(),
        ));
    }
    // from_sec1_bytes rejects points that are not on the curve.
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
        .map_err(|e| KeystoneError::InvalidPublicKey(e.to_string()))?;
    Ok(PublicKey::P256(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Identity, SignedMessage};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    /// Test-only P-256 signer. Real P-256 keys live in phone hardware and sign there.
    fn sign_p256(sk: &SigningKey, content: &str) -> SignedMessage {
        let content_hash = blake3::hash(content.as_bytes()).to_hex().to_string();
        let sig: Signature = sk.sign(content_hash.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        SignedMessage {
            author: PublicKey::P256(*sk.verifying_key()).to_wire(),
            content: content.to_string(),
            content_hash,
            signature: hex::encode(sig.to_bytes()),
        }
    }

    fn random_p256() -> SigningKey {
        SigningKey::random(&mut rand::rngs::OsRng)
    }

    #[test]
    fn p256_sign_and_verify() {
        let msg = sign_p256(&random_p256(), "front desk check-in");
        assert!(msg.verify().is_ok());
    }

    #[test]
    fn p256_signature_from_other_key_fails() {
        let mut msg = sign_p256(&random_p256(), "front desk check-in");
        msg.signature = sign_p256(&random_p256(), "front desk check-in").signature;
        assert!(msg.verify().is_err());
    }

    #[test]
    fn ed25519_wire_form_is_bare_hex() {
        let id = Identity::generate();
        let key = PublicKey::from_wire(&id.public_key_hex()).unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert_eq!(key.to_wire(), id.public_key_hex());
        assert_eq!(key.to_string(), format!("ed25519:{}", id.public_key_hex()));
    }

    #[test]
    fn display_form_roundtrips_through_parse() {
        let ed = PublicKey::from_wire(&Identity::generate().public_key_hex()).unwrap();
        let p = PublicKey::P256(*random_p256().verifying_key());
        for key in [ed, p] {
            assert_eq!(PublicKey::parse(&key.to_string()).unwrap(), key);
            assert_eq!(PublicKey::parse(&key.to_wire()).unwrap(), key);
            assert_eq!(PublicKey::from_wire(&key.to_wire()).unwrap(), key);
        }
    }

    #[test]
    fn high_s_rejected_only_by_low_s_rule() {
        let sk = random_p256();
        let msg = sign_p256(&sk, "front desk check-in");
        let low = Signature::from_slice(&hex::decode(&msg.signature).unwrap()).unwrap();
        let (r, s) = low.split_scalars();
        let high = Signature::from_scalars(r, -*s).unwrap();

        // Plain ECDSA accepts both halves; Keystone must accept only the low one.
        assert!(
            sk.verifying_key()
                .verify(msg.content_hash.as_bytes(), &high)
                .is_ok()
        );
        let key = PublicKey::P256(*sk.verifying_key());
        let high_hex = hex::encode(high.to_bytes());
        assert!(key.verify(msg.content_hash.as_bytes(), &high_hex).is_err());
    }

    #[test]
    fn uncompressed_p256_key_rejected() {
        let sk = random_p256();
        let uncompressed = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        assert!(PublicKey::from_wire(&format!("p256:{uncompressed}")).is_err());
    }

    #[test]
    fn malformed_input_errors_without_panic() {
        for s in [
            "", ":", "p256:", "p256:zz", "p256:02", "ed25519:", "abc", "x:y:z",
        ] {
            assert!(PublicKey::parse(s).is_err(), "{s:?}");
        }
        let key = PublicKey::P256(*random_p256().verifying_key());
        for sig in ["", "zz", "00", &"00".repeat(64), &"ff".repeat(64)] {
            assert!(key.verify(b"x", sig).is_err(), "{sig:?}");
        }
    }
}

//! Passkeys (WebAuthn): a person signs in with the key their phone or browser already holds,
//! before the Keystone app exists.
//!
//! A passkey does not sign Keystone's Blake3 hex. It signs
//! `authenticatorData || sha256(clientDataJSON)`, so passkeys have their own types here rather
//! than going through `SignedMessage`. Only P-256 passkeys (COSE algorithm -7, ES256) are
//! accepted for now.
//!
//! Linking (registration) is not signed: with attestation "none" the browser simply hands the
//! service a public key, and trust in it comes from the service's own page served over HTTPS.
//! Its checks stop a key made for another site, or for another moment, being linked by mistake.
//!
//! Byte fields are base64url without padding, as browsers return them.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::KeystoneError;
use crate::key::PublicKey;

const COSE_ES256: i64 = -7;
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
/// rpIdHash (32) || flags (1) || signCount (4).
const AUTH_DATA_MIN_LEN: usize = 37;
/// WebAuthn requires challenges of at least 16 random bytes.
const MIN_CHALLENGE_LEN: usize = 16;

// Bounds on remote input, checked before decoding. Real values are far smaller.
const MAX_AUTH_DATA_B64: usize = 2048;
const MAX_CLIENT_DATA_B64: usize = 4096;
const MAX_SIGNATURE_B64: usize = 128;
const MAX_PUBLIC_KEY_B64: usize = 256;

/// What the service expects of one sign-in or link. The challenge is single use.
pub struct WebAuthnExpectations<'a> {
    /// The random challenge the service issued for this ceremony (16 bytes or more).
    pub challenge: &'a [u8],
    /// The exact origin of the service's page, e.g. `https://desk.example.com`.
    pub origin: &'a str,
    /// The relying-party id the passkey belongs to, e.g. `example.com`.
    pub rp_id: &'a str,
    /// Require the authenticator to confirm the person unlocked it (fingerprint, face, PIN),
    /// not only that someone touched it.
    pub require_user_verification: bool,
}

/// Linking a passkey: from `navigator.credentials.create()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistration {
    /// `response.getPublicKey()`: the key as SubjectPublicKeyInfo DER.
    pub public_key: String,
    /// `response.getPublicKeyAlgorithm()`: a COSE algorithm number.
    pub public_key_algorithm: i64,
    /// `response.getAuthenticatorData()`.
    pub authenticator_data: String,
    /// `response.clientDataJSON`.
    pub client_data_json: String,
}

/// Signing in with a linked passkey: from `navigator.credentials.get()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAssertion {
    /// The linked key, wire form (`p256:…`), as returned by registration.
    pub author: String,
    /// `response.authenticatorData`.
    pub authenticator_data: String,
    /// `response.clientDataJSON`.
    pub client_data_json: String,
    /// `response.signature`: ECDSA, DER-encoded.
    pub signature: String,
}

/// A passkey that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPasskey {
    pub author: PublicKey,
    /// The authenticator's counter. If both the stored and the new count are non-zero and the
    /// new one is not larger, the passkey may have been copied; what to do is the service's call.
    /// Synced passkeys always report 0.
    pub sign_count: u32,
    /// The person unlocked the key (fingerprint, face, PIN), not only touched it.
    pub user_verified: bool,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

impl WebAuthnRegistration {
    pub fn verify(
        &self,
        expected: &WebAuthnExpectations,
    ) -> Result<VerifiedPasskey, KeystoneError> {
        if self.public_key_algorithm != COSE_ES256 {
            return Err(KeystoneError::UnsupportedAlgorithm(format!(
                "COSE {} (only ES256, -7, is accepted)",
                self.public_key_algorithm
            )));
        }
        let client_data = decode(
            &self.client_data_json,
            MAX_CLIENT_DATA_B64,
            "client_data_json",
        )?;
        check_client_data(&client_data, "webauthn.create", expected)?;
        let auth_data = decode(
            &self.authenticator_data,
            MAX_AUTH_DATA_B64,
            "authenticator_data",
        )?;
        let (sign_count, user_verified) = check_authenticator_data(&auth_data, expected)?;

        let spki = decode(&self.public_key, MAX_PUBLIC_KEY_B64, "public_key")?;
        // Rejects keys that are not P-256 or not on the curve.
        let key = p256::ecdsa::VerifyingKey::from_public_key_der(&spki)
            .map_err(|e| KeystoneError::InvalidPublicKey(e.to_string()))?;

        Ok(VerifiedPasskey {
            author: PublicKey::P256(key),
            sign_count,
            user_verified,
        })
    }
}

impl WebAuthnAssertion {
    pub fn verify(
        &self,
        expected: &WebAuthnExpectations,
    ) -> Result<VerifiedPasskey, KeystoneError> {
        let author = PublicKey::from_wire(&self.author)?;
        let PublicKey::P256(key) = &author else {
            return Err(KeystoneError::UnsupportedAlgorithm(format!(
                "{} passkeys (only p256 is accepted)",
                author.algorithm().as_str()
            )));
        };

        let client_data = decode(
            &self.client_data_json,
            MAX_CLIENT_DATA_B64,
            "client_data_json",
        )?;
        check_client_data(&client_data, "webauthn.get", expected)?;
        let auth_data = decode(
            &self.authenticator_data,
            MAX_AUTH_DATA_B64,
            "authenticator_data",
        )?;
        let (sign_count, user_verified) = check_authenticator_data(&auth_data, expected)?;

        // Authenticators do not normalise s, so unlike SignedMessage both halves are accepted.
        // Each challenge is single use, so a second valid signature cannot be replayed.
        let der = decode(&self.signature, MAX_SIGNATURE_B64, "signature")?;
        let signature =
            p256::ecdsa::Signature::from_der(&der).map_err(|_| KeystoneError::InvalidSignature)?;
        let mut signed = auth_data;
        signed.extend_from_slice(&Sha256::digest(&client_data));
        key.verify(&signed, &signature)
            .map_err(|_| KeystoneError::InvalidSignature)?;

        Ok(VerifiedPasskey {
            author,
            sign_count,
            user_verified,
        })
    }
}

fn decode(value: &str, max_len: usize, field: &str) -> Result<Vec<u8>, KeystoneError> {
    if value.len() > max_len {
        return Err(KeystoneError::WebAuthn(format!("{field} is too long")));
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| KeystoneError::WebAuthn(format!("{field} is not base64url")))
}

/// clientDataJSON is parsed, never compared to a template: browsers add fields of their own.
fn check_client_data(
    raw: &[u8],
    kind: &str,
    expected: &WebAuthnExpectations,
) -> Result<(), KeystoneError> {
    if expected.challenge.len() < MIN_CHALLENGE_LEN {
        return Err(KeystoneError::WebAuthn(format!(
            "expected challenge must be at least {MIN_CHALLENGE_LEN} bytes"
        )));
    }
    let data: ClientData = serde_json::from_slice(raw)
        .map_err(|e| KeystoneError::WebAuthn(format!("client_data_json: {e}")))?;
    if data.kind != kind {
        return Err(KeystoneError::WebAuthn(format!(
            "type is {:?}, expected {kind:?}",
            data.kind
        )));
    }
    let challenge = URL_SAFE_NO_PAD
        .decode(&data.challenge)
        .map_err(|_| KeystoneError::WebAuthn("challenge is not base64url".into()))?;
    if challenge != expected.challenge {
        return Err(KeystoneError::WebAuthn("challenge does not match".into()));
    }
    if data.origin != expected.origin {
        return Err(KeystoneError::WebAuthn(format!(
            "origin {:?} does not match",
            data.origin
        )));
    }
    if data.cross_origin {
        return Err(KeystoneError::WebAuthn(
            "made inside a cross-origin frame".into(),
        ));
    }
    Ok(())
}

/// Returns (sign_count, user_verified).
fn check_authenticator_data(
    auth_data: &[u8],
    expected: &WebAuthnExpectations,
) -> Result<(u32, bool), KeystoneError> {
    if auth_data.len() < AUTH_DATA_MIN_LEN {
        return Err(KeystoneError::WebAuthn(
            "authenticator_data is too short".into(),
        ));
    }
    if auth_data[..32] != Sha256::digest(expected.rp_id.as_bytes())[..] {
        return Err(KeystoneError::WebAuthn(
            "made for a different relying party".into(),
        ));
    }
    let flags = auth_data[32];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(KeystoneError::WebAuthn("user was not present".into()));
    }
    let user_verified = flags & FLAG_USER_VERIFIED != 0;
    if expected.require_user_verification && !user_verified {
        return Err(KeystoneError::WebAuthn("user was not verified".into()));
    }
    let count = [auth_data[33], auth_data[34], auth_data[35], auth_data[36]];
    Ok((u32::from_be_bytes(count), user_verified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Vec<Value> {
        let file: Value =
            serde_json::from_str(include_str!("../test-vectors/webauthn.json")).unwrap();
        file["cases"].as_array().unwrap().clone()
    }

    fn run(case: &Value, challenge: &[u8]) -> Result<VerifiedPasskey, KeystoneError> {
        let e = &case["expect"];
        let expected = WebAuthnExpectations {
            challenge,
            origin: e["origin"].as_str().unwrap(),
            rp_id: e["rp_id"].as_str().unwrap(),
            require_user_verification: e["require_user_verification"].as_bool().unwrap(),
        };
        let msg = case["message"].clone();
        match case["kind"].as_str().unwrap() {
            "registration" => serde_json::from_value::<WebAuthnRegistration>(msg)
                .unwrap()
                .verify(&expected),
            "assertion" => serde_json::from_value::<WebAuthnAssertion>(msg)
                .unwrap()
                .verify(&expected),
            other => panic!("unknown kind {other}"),
        }
    }

    fn challenge(case: &Value) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(case["expect"]["challenge"].as_str().unwrap())
            .unwrap()
    }

    fn case(name: &str) -> Value {
        vectors().into_iter().find(|c| c["name"] == name).unwrap()
    }

    #[test]
    fn shared_test_vectors() {
        for case in vectors() {
            let name = case["name"].as_str().unwrap();
            let result = run(&case, &challenge(&case));
            assert_eq!(
                result.is_ok(),
                case["valid"].as_bool().unwrap(),
                "vector {name}: {result:?}"
            );
            let Ok(verified) = result else { continue };
            if let Some(count) = case["sign_count"].as_u64() {
                assert_eq!(u64::from(verified.sign_count), count, "vector {name}");
            }
            if let Some(author) = case["author"].as_str() {
                assert_eq!(verified.author.to_wire(), author, "vector {name}");
            }
        }
    }

    #[test]
    fn registered_key_signs_the_assertion() {
        let reg = case("chrome_registration");
        let linked = run(&reg, &challenge(&reg)).unwrap();
        let asn = case("chrome_assertion");
        assert_eq!(asn["message"]["author"], linked.author.to_wire());
        assert!(run(&asn, &challenge(&asn)).unwrap().user_verified);
    }

    #[test]
    fn assertion_cannot_be_used_as_registration() {
        let asn = case("chrome_assertion");
        let reg = case("chrome_registration");
        let mut swapped = reg.clone();
        swapped["message"]["client_data_json"] = asn["message"]["client_data_json"].clone();
        assert!(run(&swapped, &challenge(&asn)).is_err());
    }

    #[test]
    fn ed25519_author_is_unsupported() {
        assert!(matches!(
            run(&case("ed25519_author"), &challenge(&case("ed25519_author"))),
            Err(KeystoneError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn unsupported_registration_algorithm() {
        let mut reg = case("chrome_registration");
        reg["message"]["public_key_algorithm"] = (-8).into();
        assert!(matches!(
            run(&reg, &challenge(&reg)),
            Err(KeystoneError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn short_expected_challenge_rejected() {
        let asn = case("chrome_assertion");
        let err = run(&asn, &challenge(&asn)[..15]).unwrap_err();
        assert!(err.to_string().contains("at least 16 bytes"), "{err}");
    }

    #[test]
    fn malformed_and_oversized_input_errors_without_panic() {
        let asn = case("chrome_assertion");
        let c = challenge(&asn);
        let long = "A".repeat(10_000);
        for field in ["authenticator_data", "client_data_json", "signature"] {
            for bad in ["", "!!", "AAAA", "AA==", long.as_str()] {
                let mut broken = asn.clone();
                broken["message"][field] = bad.into();
                assert!(run(&broken, &c).is_err(), "{field} = {bad:.10}");
            }
        }
        let mut broken = case("chrome_registration");
        broken["message"]["public_key"] = "AAAA".into();
        assert!(run(&broken, &challenge(&broken)).is_err());
    }
}

//! Signing in with a key a browser holds, bound to the site it was signed on.
//!
//! A bare challenge says nothing about where it was signed. A page on one site could fetch a
//! real challenge from another site, have the person approve it, and pass the signature on. So
//! the browser (the Keystone extension, which knows the page's real origin) signs the origin
//! together with the challenge, and the service checks both:
//!
//! 1. The service issues a random challenge: 16 to 64 bytes, lowercase hex, single use.
//! 2. The browser signs `sign_in_content(origin, challenge)` with the `SignedMessage` rule.
//! 3. The service runs `verify_sign_in` with its own origin and the challenge it issued, then
//!    marks the challenge used. A signature made on any other site fails.

use serde::{Deserialize, Serialize};

use crate::error::KeystoneError;
use crate::identity::SignedMessage;
use crate::key::PublicKey;
use crate::request::{is_hex_token, validate_origin};

pub const SIGN_IN_KIND: &str = "keystone.signin";
const VERSION: u32 = 1;
/// Bound on a sign-in's content, checked before parsing.
const MAX_CONTENT_LEN: usize = 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignInContent {
    kind: String,
    v: u32,
    origin: String,
    challenge: String,
}

/// The text a browser signs to sign in at `origin` with `challenge`.
pub fn sign_in_content(origin: &str, challenge: &str) -> Result<String, KeystoneError> {
    validate(origin, challenge)?;
    Ok(serde_json::to_string(&SignInContent {
        kind: SIGN_IN_KIND.into(),
        v: VERSION,
        origin: origin.into(),
        challenge: challenge.into(),
    })?)
}

/// The service checks a sign-in against its own origin and the challenge it issued. On
/// success it gets the person's key; it must then mark the challenge used.
pub fn verify_sign_in(
    signed: &SignedMessage,
    expected_origin: &str,
    expected_challenge: &str,
) -> Result<PublicKey, KeystoneError> {
    let fail = |m: &str| Err(KeystoneError::Request(m.into()));
    if signed.content.len() > MAX_CONTENT_LEN {
        return fail("sign-in is too long");
    }
    signed.verify()?;
    let content: SignInContent = serde_json::from_str(&signed.content)
        .map_err(|e| KeystoneError::Request(format!("not a sign-in: {e}")))?;
    if content.kind != SIGN_IN_KIND {
        return fail("kind is not keystone.signin");
    }
    if content.v != VERSION {
        return fail("unsupported version");
    }
    validate(&content.origin, &content.challenge)?;
    if content.origin != expected_origin {
        return fail("signed on a different site");
    }
    if content.challenge != expected_challenge {
        return fail("signed for a different challenge");
    }
    PublicKey::from_wire(&signed.author)
}

fn validate(origin: &str, challenge: &str) -> Result<(), KeystoneError> {
    validate_origin(origin)?;
    if !is_hex_token(challenge) {
        return Err(KeystoneError::Request(
            "challenge must be 16 to 64 bytes of lowercase hex".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use serde_json::Value;

    const ORIGIN: &str = "https://desk.example.com";

    #[test]
    fn shared_test_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../test-vectors/sign_in.json")).unwrap();
        let cases = vectors["cases"].as_array().unwrap();
        assert!(cases.len() >= 18);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let signed: SignedMessage = serde_json::from_value(case["signed"].clone()).unwrap();
            let result = verify_sign_in(
                &signed,
                case["expected_origin"].as_str().unwrap(),
                case["expected_challenge"].as_str().unwrap(),
            );
            assert_eq!(
                result.is_ok(),
                case["valid"].as_bool().unwrap(),
                "{name}: {result:?}"
            );
        }
    }

    #[test]
    fn content_matches_the_vectors_byte_for_byte() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../test-vectors/sign_in.json")).unwrap();
        let valid = &vectors["cases"][0];
        assert_eq!(valid["name"], "valid");
        let built = sign_in_content(
            valid["expected_origin"].as_str().unwrap(),
            valid["expected_challenge"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(built, valid["signed"]["content"].as_str().unwrap());
    }

    #[test]
    fn round_trip_returns_the_signer() {
        let id = Identity::generate();
        let challenge = "ab".repeat(32);
        let signed = id.sign(&sign_in_content(ORIGIN, &challenge).unwrap());
        let key = verify_sign_in(&signed, ORIGIN, &challenge).unwrap();
        assert_eq!(key, id.public_key());
    }

    #[test]
    fn signature_made_on_one_site_fails_at_another() {
        let id = Identity::generate();
        let challenge = "ab".repeat(32);
        let signed = id.sign(&sign_in_content("https://other.example.com", &challenge).unwrap());
        assert!(verify_sign_in(&signed, ORIGIN, &challenge).is_err());
    }

    #[test]
    fn content_refuses_bad_origin_or_challenge() {
        let challenge = "ab".repeat(32);
        for origin in [
            "",
            "http://desk.example.com",
            "https://desk.example.com/",
            "HTTPS://x.com",
        ] {
            assert!(sign_in_content(origin, &challenge).is_err(), "{origin:?}");
        }
        for c in ["", "AB", &"ab".repeat(15), &"ab".repeat(65), "{\"kind\":1}"] {
            assert!(sign_in_content(ORIGIN, c).is_err(), "{c:?}");
        }
    }

    #[test]
    fn huge_content_is_refused_before_parsing() {
        // A valid sign-in, padded with whitespace JSON allows, so only the length check can
        // refuse it.
        let id = Identity::generate();
        let challenge = "ab".repeat(32);
        let content = sign_in_content(ORIGIN, &challenge).unwrap();
        let fits = format!("{content}{}", " ".repeat(MAX_CONTENT_LEN - content.len()));
        assert!(verify_sign_in(&id.sign(&fits), ORIGIN, &challenge).is_ok());
        let padded = format!(
            "{content}{}",
            " ".repeat(MAX_CONTENT_LEN + 1 - content.len())
        );
        assert!(verify_sign_in(&id.sign(&padded), ORIGIN, &challenge).is_err());
    }
}

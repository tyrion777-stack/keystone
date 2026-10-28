//! Signed requests from a service, and the approvals that answer them.
//!
//! A QR or link used to say `origin: "…"` and the phone believed it. Now a service signs every
//! request with its own Keystone key, and the person's approval signs that exact request back:
//!
//! 1. The service builds a `ServiceRequest` and signs it: a `SignedMessage` whose content is
//!    the request as JSON.
//! 2. The phone runs `ServiceRequest::verify`, shows the service's name, and compares the
//!    service's key with the one it pinned on first link (the app's job, not this crate's).
//! 3. The person approves: `VerifiedRequest::approve` signs the request's hash, the service's
//!    key and the purpose, so the approval cannot be replayed for another request, another
//!    service or another purpose.
//! 4. The service runs `verify_approval` against the request it issued, then marks the nonce
//!    used. Remembering used nonces is the service's job; each nonce must be accepted once.
//!
//! A passkey can approve too: use `VerifiedRequest::passkey_challenge` as the WebAuthn challenge.
//!
//! The service name is only a label. Anyone can sign a request that claims any name; what the
//! person can trust is the service's key, pinned on first link.

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::error::KeystoneError;
use crate::identity::{Identity, SignedMessage};
use crate::key::PublicKey;

pub const REQUEST_KIND: &str = "keystone.request";
pub const APPROVAL_KIND: &str = "keystone.approval";
const VERSION: u32 = 1;

/// The longest a request may stay valid.
pub const MAX_LIFETIME_SECS: u64 = 600;
/// Clocks on phones and desks disagree; this much is tolerated either way.
pub const CLOCK_SKEW_SECS: u64 = 60;

const NONCE_BYTES: usize = 16;
const MAX_NONCE_HEX: usize = 128;
const MAX_SERVICE_NAME_CHARS: usize = 64;
const MAX_ORIGIN_LEN: usize = 256;
const MAX_PAYLOAD_LEN: usize = 2048;
/// Bound on a signed request or approval's content, checked before parsing.
const MAX_CONTENT_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    /// Link this person's key to the service, once.
    Link,
    /// Prove it is the linked person, now.
    CheckIn,
    /// Sign the text in `payload`.
    Sign,
}

/// What a service asks of a person. Signed by the service as a `SignedMessage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequest {
    /// Always `keystone.request`, so no other signed message can pass as a request.
    pub kind: String,
    pub v: u32,
    /// The name shown to the person. A label only; trust the key, not the name.
    pub service: String,
    /// The service's web origin, e.g. `https://desk.example.com`.
    pub origin: String,
    pub purpose: Purpose,
    /// 16+ random bytes, lowercase hex. Single use.
    pub nonce: String,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds; at most `MAX_LIFETIME_SECS` after `issued_at`.
    pub expires_at: u64,
    /// The text to sign. Present exactly when `purpose` is `sign`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// A request whose signature and fields have been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRequest {
    /// The key that signed the request. Compare with the key pinned for this service.
    pub service_key: PublicKey,
    pub request: ServiceRequest,
    /// The request's Blake3 content hash, which approvals sign.
    pub hash: String,
}

/// What the person signs to approve a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalContent {
    kind: String,
    v: u32,
    /// The approved request's content hash.
    request: String,
    /// The service key that signed the request, wire form.
    service_key: String,
    purpose: Purpose,
}

/// An approval that matches a request the service issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedApproval {
    /// The person who approved.
    pub person: PublicKey,
    pub purpose: Purpose,
    /// Mark this used; never accept it again.
    pub nonce: String,
}

impl ServiceRequest {
    /// A new request with a fresh random nonce, valid for `lifetime_secs` from `now`.
    pub fn new(
        service: &str,
        origin: &str,
        purpose: Purpose,
        payload: Option<String>,
        now: u64,
        lifetime_secs: u64,
    ) -> Result<Self, KeystoneError> {
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let expires_at = now
            .checked_add(lifetime_secs)
            .ok_or_else(|| KeystoneError::Request("lifetime overflows".into()))?;
        let request = Self {
            kind: REQUEST_KIND.into(),
            v: VERSION,
            service: service.into(),
            origin: origin.into(),
            purpose,
            nonce: hex::encode(nonce),
            issued_at: now,
            expires_at,
            payload,
        };
        request.validate(now)?;
        Ok(request)
    }

    /// Sign this request with the service's identity.
    pub fn sign(&self, service: &Identity) -> Result<SignedMessage, KeystoneError> {
        Ok(service.sign(&serde_json::to_string(self)?))
    }

    /// Check a signed request: signature, every field, and that it is valid at `now`.
    pub fn verify(signed: &SignedMessage, now: u64) -> Result<VerifiedRequest, KeystoneError> {
        if signed.content.len() > MAX_CONTENT_LEN {
            return Err(KeystoneError::Request("request is too long".into()));
        }
        signed.verify()?;
        let request: ServiceRequest = serde_json::from_str(&signed.content)
            .map_err(|e| KeystoneError::Request(format!("not a request: {e}")))?;
        request.validate(now)?;
        Ok(VerifiedRequest {
            service_key: PublicKey::from_wire(&signed.author)?,
            request,
            hash: signed.content_hash.clone(),
        })
    }

    fn validate(&self, now: u64) -> Result<(), KeystoneError> {
        let fail = |m: &str| Err(KeystoneError::Request(m.into()));
        if self.kind != REQUEST_KIND {
            return fail("kind is not keystone.request");
        }
        if self.v != VERSION {
            return fail("unsupported version");
        }
        validate_service_name(&self.service)?;
        validate_origin(&self.origin)?;
        validate_nonce(&self.nonce)?;

        if self.expires_at <= self.issued_at {
            return fail("expires before it is issued");
        }
        if self.expires_at - self.issued_at > MAX_LIFETIME_SECS {
            return fail("lifetime is longer than 10 minutes");
        }
        if self.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
            return fail("issued in the future");
        }
        if now >= self.expires_at.saturating_add(CLOCK_SKEW_SECS) {
            return fail("expired");
        }

        match (&self.purpose, &self.payload) {
            (Purpose::Sign, None) => fail("a sign request needs a payload"),
            (Purpose::Sign, Some(p)) if p.is_empty() || p.len() > MAX_PAYLOAD_LEN => {
                fail("payload must be 1 to 2048 bytes")
            }
            (Purpose::Link | Purpose::CheckIn, Some(_)) => {
                fail("only a sign request has a payload")
            }
            _ => Ok(()),
        }
    }
}

impl VerifiedRequest {
    /// The person approves this request.
    pub fn approve(&self, person: &Identity) -> Result<SignedMessage, KeystoneError> {
        let content = ApprovalContent {
            kind: APPROVAL_KIND.into(),
            v: VERSION,
            request: self.hash.clone(),
            service_key: self.service_key.to_wire(),
            purpose: self.request.purpose,
        };
        Ok(person.sign(&serde_json::to_string(&content)?))
    }

    /// Use as the WebAuthn challenge to approve this request with a passkey: the request's
    /// 32-byte Blake3 hash, so the passkey signature is bound to this exact request.
    pub fn passkey_challenge(&self) -> Result<Vec<u8>, KeystoneError> {
        Ok(hex::decode(&self.hash)?)
    }
}

/// The service checks an approval against the signed request it issued, at `now` on its own
/// clock. On success, mark `nonce` used and never accept it again.
pub fn verify_approval(
    approval: &SignedMessage,
    issued: &SignedMessage,
    now: u64,
) -> Result<VerifiedApproval, KeystoneError> {
    let request = ServiceRequest::verify(issued, now)?;
    if approval.content.len() > MAX_CONTENT_LEN {
        return Err(KeystoneError::Request("approval is too long".into()));
    }
    approval.verify()?;
    let content: ApprovalContent = serde_json::from_str(&approval.content)
        .map_err(|e| KeystoneError::Request(format!("not an approval: {e}")))?;
    let fail = |m: &str| Err(KeystoneError::Request(m.into()));
    if content.kind != APPROVAL_KIND {
        return fail("kind is not keystone.approval");
    }
    if content.v != VERSION {
        return fail("unsupported version");
    }
    if content.request != request.hash {
        return fail("approval is for a different request");
    }
    if content.service_key != request.service_key.to_wire() {
        return fail("approval is for a different service key");
    }
    if content.purpose != request.request.purpose {
        return fail("approval is for a different purpose");
    }
    Ok(VerifiedApproval {
        person: PublicKey::from_wire(&approval.author)?,
        purpose: content.purpose,
        nonce: request.request.nonce,
    })
}

/// A name is shown to people, so it must not be able to fake its own layout: no control
/// characters (newlines) and no bidirectional overrides (which can reverse text on screen).
fn validate_service_name(name: &str) -> Result<(), KeystoneError> {
    let chars = name.chars().count();
    if chars == 0 || chars > MAX_SERVICE_NAME_CHARS || name.trim() != name {
        return Err(KeystoneError::Request(
            "service name must be 1 to 64 characters, no outer spaces".into(),
        ));
    }
    let bidi = |c: char| matches!(c, '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
    if name.chars().any(|c| c.is_control() || bidi(c)) {
        return Err(KeystoneError::Request(
            "service name has control or direction characters".into(),
        ));
    }
    Ok(())
}

/// `https://host[:port]`, or `http://localhost[:port]` for development. Lowercase, no path,
/// no user info, so one origin has one spelling.
fn validate_origin(origin: &str) -> Result<(), KeystoneError> {
    let bad = || {
        Err(KeystoneError::Request(format!(
            "origin {origin:?} is not allowed"
        )))
    };
    if origin.len() > MAX_ORIGIN_LEN {
        return bad();
    }
    let (host, port) = if let Some(rest) = origin.strip_prefix("https://") {
        rest.split_once(':')
            .map_or((rest, None), |(h, p)| (h, Some(p)))
    } else if let Some(rest) = origin.strip_prefix("http://localhost") {
        if !(rest.is_empty() || rest.starts_with(':')) {
            return bad();
        }
        ("localhost", rest.strip_prefix(':'))
    } else {
        return bad();
    };
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..");
    let port_ok = match port {
        None => true,
        Some(p) => !p.is_empty() && !p.starts_with('0') && p.len() <= 5 && p.parse::<u16>().is_ok(),
    };
    if host_ok && port_ok { Ok(()) } else { bad() }
}

fn validate_nonce(nonce: &str) -> Result<(), KeystoneError> {
    let len_ok = nonce.len() >= NONCE_BYTES * 2
        && nonce.len() <= MAX_NONCE_HEX
        && nonce.len().is_multiple_of(2);
    if len_ok
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(KeystoneError::Request(
            "nonce must be 16 to 64 bytes of lowercase hex".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const NOW: u64 = 1_800_000_000;

    fn msg(v: &Value) -> SignedMessage {
        serde_json::from_value(v.clone()).unwrap()
    }

    #[test]
    fn shared_test_vectors() {
        let file: Value =
            serde_json::from_str(include_str!("../test-vectors/service_request.json")).unwrap();
        for case in file["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let now = case["now"].as_u64().unwrap();
            let valid = case["valid"].as_bool().unwrap();
            match case["kind"].as_str().unwrap() {
                "request" => {
                    let result = ServiceRequest::verify(&msg(&case["signed"]), now);
                    assert_eq!(result.is_ok(), valid, "vector {name}: {result:?}");
                }
                "approval" => {
                    let result =
                        verify_approval(&msg(&case["approval"]), &msg(&case["issued"]), now);
                    assert_eq!(result.is_ok(), valid, "vector {name}: {result:?}");
                    if let (Ok(ok), Some(person)) = (result, case["person"].as_str()) {
                        assert_eq!(ok.person.to_wire(), person, "vector {name}");
                    }
                }
                other => panic!("unknown kind {other}"),
            }
        }
    }

    #[test]
    fn round_trip_request_and_approval() {
        let desk = Identity::generate();
        let person = Identity::generate();
        let request = ServiceRequest::new(
            "Front desk",
            "https://desk.example.com",
            Purpose::CheckIn,
            None,
            NOW,
            120,
        )
        .unwrap();
        let issued = request.sign(&desk).unwrap();

        let seen = ServiceRequest::verify(&issued, NOW + 5).unwrap();
        assert_eq!(seen.service_key, desk.public_key());
        assert_eq!(seen.request, request);

        let approval = seen.approve(&person).unwrap();
        let ok = verify_approval(&approval, &issued, NOW + 10).unwrap();
        assert_eq!(ok.person, person.public_key());
        assert_eq!(ok.purpose, Purpose::CheckIn);
        assert_eq!(ok.nonce, request.nonce);
    }

    #[test]
    fn approval_for_one_desk_fails_at_another() {
        let desk = Identity::generate();
        let copycat = Identity::generate();
        let person = Identity::generate();
        let request = ServiceRequest::new(
            "Front desk",
            "https://desk.example.com",
            Purpose::Link,
            None,
            NOW,
            60,
        )
        .unwrap();
        // The copycat re-signs the same content under its own key.
        let real = request.sign(&desk).unwrap();
        let copied = request.sign(&copycat).unwrap();
        assert_eq!(real.content_hash, copied.content_hash);

        let approval = ServiceRequest::verify(&copied, NOW)
            .unwrap()
            .approve(&person)
            .unwrap();
        assert!(verify_approval(&approval, &real, NOW).is_err());
    }

    #[test]
    fn nonces_are_fresh() {
        let a = ServiceRequest::new(
            "Front desk",
            "https://desk.example.com",
            Purpose::Link,
            None,
            NOW,
            60,
        )
        .unwrap();
        let b = ServiceRequest::new(
            "Front desk",
            "https://desk.example.com",
            Purpose::Link,
            None,
            NOW,
            60,
        )
        .unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(a.nonce.len(), NONCE_BYTES * 2);
    }

    #[test]
    fn new_rejects_what_verify_rejects() {
        let new = |origin: &str, purpose, payload: Option<&str>, life| {
            ServiceRequest::new(
                "Front desk",
                origin,
                purpose,
                payload.map(String::from),
                NOW,
                life,
            )
        };
        assert!(new("http://desk.example.com", Purpose::Link, None, 60).is_err());
        assert!(new("https://desk.example.com", Purpose::Sign, None, 60).is_err());
        assert!(new("https://desk.example.com", Purpose::Link, None, 601).is_err());
        assert!(new("https://desk.example.com", Purpose::Link, None, u64::MAX).is_err());
        assert!(new("https://desk.example.com", Purpose::Sign, Some("ok"), 60).is_ok());
    }

    #[test]
    fn passkey_challenge_is_the_request_hash() {
        let request = ServiceRequest::new(
            "Front desk",
            "https://desk.example.com",
            Purpose::CheckIn,
            None,
            NOW,
            60,
        )
        .unwrap();
        let issued = request.sign(&Identity::generate()).unwrap();
        let challenge = ServiceRequest::verify(&issued, NOW)
            .unwrap()
            .passkey_challenge()
            .unwrap();
        assert_eq!(
            challenge,
            blake3::hash(issued.content.as_bytes()).as_bytes()
        );
    }

    #[test]
    fn origins() {
        for ok in [
            "https://example.com",
            "https://desk.example.com:8443",
            "http://localhost",
            "http://localhost:8765",
        ] {
            assert!(validate_origin(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "https://",
            "https://:443",
            "https://example.com:",
            "https://example.com:0443",
            "https://.example.com",
            "https://example..com",
            "https://example.com/x",
            "http://localhost.example.com",
            "http://localhostx",
            "ftp://example.com",
            "https://exa mple.com",
            "https://example.com:65536",
        ] {
            assert!(validate_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn malformed_input_errors_without_panic() {
        let id = Identity::generate();
        for content in ["", "{}", "null", "[]", "{\"kind\":1}", &"x".repeat(5000)] {
            let signed = id.sign(content);
            assert!(
                ServiceRequest::verify(&signed, NOW).is_err(),
                "{content:.20}"
            );
            assert!(verify_approval(&signed, &signed, NOW).is_err());
        }
        // Oversized input is refused before any signature check or parsing.
        let huge = id.sign(&"x".repeat(MAX_CONTENT_LEN + 1));
        let err = ServiceRequest::verify(&huge, NOW).unwrap_err();
        assert!(err.to_string().contains("request is too long"), "{err}");
        let small = id.sign("{}");
        let err = verify_approval(&huge, &small, NOW).unwrap_err();
        assert!(
            !err.to_string().contains("approval is too long"),
            "issued is checked first"
        );
        let issued = ServiceRequest::new(
            "Front desk",
            "https://example.com",
            Purpose::Link,
            None,
            NOW,
            60,
        )
        .unwrap()
        .sign(&id)
        .unwrap();
        let err = verify_approval(&huge, &issued, NOW).unwrap_err();
        assert!(err.to_string().contains("approval is too long"), "{err}");

        // Times at the edges of u64 must not overflow.
        let mut r = ServiceRequest::new(
            "Front desk",
            "https://example.com",
            Purpose::Link,
            None,
            NOW,
            60,
        )
        .unwrap();
        r.issued_at = u64::MAX - 1;
        r.expires_at = u64::MAX;
        assert!(r.validate(u64::MAX - 1).is_ok());
        assert!(r.validate(u64::MAX).is_err());
        assert!(r.validate(0).is_err());
    }
}

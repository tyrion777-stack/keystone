//! keystone-core's checks for JavaScript, as WebAssembly, so the app and the extension run the
//! same Rust that services run, not a copy of it.
//!
//! One call, JSON in and JSON out: `handle` does the work and is tested natively; the exports
//! at the bottom only move bytes across the WebAssembly boundary. Every answer is
//! `{"ok":true,...}` or `{"ok":false,"error":"..."}`.

use keystone_core::{
    KeystoneError, ServiceRequest, SignedMessage, sign_in_content, verify_approval, verify_sign_in,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Call {
    /// Check a service's signed request at `now` (Unix seconds). Also returns the text the
    /// person signs to approve it.
    VerifyRequest { signed: SignedMessage, now: u64 },
    /// The text a browser signs to sign in at `origin`.
    SignInContent { origin: String, challenge: String },
    /// What a service runs on a sign-in.
    VerifySignIn {
        signed: SignedMessage,
        origin: String,
        challenge: String,
    },
    /// What a service runs on an approval.
    VerifyApproval {
        approval: SignedMessage,
        issued: SignedMessage,
        now: u64,
    },
}

/// Answer one call. Never panics: a bad call is an error answer.
pub fn handle(input: &str) -> String {
    let answer = serde_json::from_str::<Call>(input)
        .map_err(|e| format!("bad call: {e}"))
        .and_then(|call| run(call).map_err(|e| e.to_string()));
    match answer {
        Ok(mut value) => {
            value["ok"] = json!(true);
            value.to_string()
        }
        Err(error) => json!({ "ok": false, "error": error }).to_string(),
    }
}

fn run(call: Call) -> Result<Value, KeystoneError> {
    Ok(match call {
        Call::VerifyRequest { signed, now } => {
            let verified = ServiceRequest::verify(&signed, now)?;
            json!({
                "service_key": verified.service_key.to_wire(),
                "request": verified.request,
                "hash": verified.hash,
                "approval_content": verified.approval_content()?,
            })
        }
        Call::SignInContent { origin, challenge } => {
            json!({ "content": sign_in_content(&origin, &challenge)? })
        }
        Call::VerifySignIn {
            signed,
            origin,
            challenge,
        } => json!({ "person": verify_sign_in(&signed, &origin, &challenge)?.to_wire() }),
        Call::VerifyApproval {
            approval,
            issued,
            now,
        } => {
            let verified = verify_approval(&approval, &issued, now)?;
            json!({
                "person": verified.person.to_wire(),
                "purpose": verified.purpose,
                "nonce": verified.nonce,
            })
        }
    })
}

#[cfg(target_arch = "wasm32")]
mod exports {
    // The boundary: JavaScript asks for a buffer, writes the call's UTF-8 into it, calls
    // `ks_call`, reads the answer, and frees both buffers.

    fn no_randomness(_: &mut [u8]) -> Result<(), getrandom::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }
    getrandom::register_custom_getrandom!(no_randomness);

    #[unsafe(no_mangle)]
    pub extern "C" fn ks_alloc(len: usize) -> *mut u8 {
        let mut buf = Vec::<u8>::with_capacity(len);
        let ptr = buf.as_mut_ptr();
        std::mem::forget(buf);
        ptr
    }

    /// # Safety
    /// `ptr` and `len` must come from `ks_alloc`, or from an answer of `ks_call`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn ks_free(ptr: *mut u8, len: usize) {
        drop(unsafe { Vec::from_raw_parts(ptr, 0, len) });
    }

    /// Takes the call written at `ptr`, frees it, and returns the answer as
    /// `(pointer << 32) | length`. The caller frees the answer with `ks_free`.
    ///
    /// # Safety
    /// `ptr` and `len` must come from `ks_alloc`, with `len` bytes written.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn ks_call(ptr: *mut u8, len: usize) -> u64 {
        let input = unsafe { Vec::from_raw_parts(ptr, len, len) };
        let answer = match std::str::from_utf8(&input) {
            Ok(text) => super::handle(text),
            Err(_) => r#"{"ok":false,"error":"call is not UTF-8"}"#.to_string(),
        };
        let mut bytes = answer.into_bytes().into_boxed_slice();
        let (out_ptr, out_len) = (bytes.as_mut_ptr(), bytes.len());
        std::mem::forget(bytes);
        ((out_ptr as u64) << 32) | out_len as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(v: Value) -> Value {
        serde_json::from_str(&handle(&v.to_string())).unwrap()
    }

    #[test]
    fn service_request_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../test-vectors/service_request.json")).unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let answer = match case["kind"].as_str().unwrap() {
                "request" => call(json!({
                    "op": "verify_request", "signed": case["signed"], "now": case["now"],
                })),
                _ => call(json!({
                    "op": "verify_approval", "approval": case["approval"],
                    "issued": case["issued"], "now": case["now"],
                })),
            };
            assert_eq!(answer["ok"], case["valid"], "{}: {answer}", case["name"]);
        }
    }

    #[test]
    fn sign_in_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../test-vectors/sign_in.json")).unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let answer = call(json!({
                "op": "verify_sign_in", "signed": case["signed"],
                "origin": case["expected_origin"], "challenge": case["expected_challenge"],
            }));
            assert_eq!(answer["ok"], case["valid"], "{}: {answer}", case["name"]);
        }
        let valid = &vectors["cases"][0];
        let built = call(json!({
            "op": "sign_in_content",
            "origin": valid["expected_origin"], "challenge": valid["expected_challenge"],
        }));
        assert_eq!(built["content"], valid["signed"]["content"]);
    }

    #[test]
    fn verified_request_carries_what_the_screen_and_the_approval_need() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../test-vectors/service_request.json")).unwrap();
        let case = &vectors["cases"][0];
        let answer =
            call(json!({"op": "verify_request", "signed": case["signed"], "now": case["now"]}));
        assert_eq!(answer["ok"], true);
        assert_eq!(answer["service_key"], case["signed"]["author"]);
        assert_eq!(answer["hash"], case["signed"]["content_hash"]);
        assert_eq!(answer["request"]["service"], "Front desk");
        let approval: Value =
            serde_json::from_str(answer["approval_content"].as_str().unwrap()).unwrap();
        assert_eq!(approval["kind"], "keystone.approval");
        assert_eq!(approval["request"], case["signed"]["content_hash"]);
    }

    #[test]
    fn bad_calls_are_error_answers() {
        for input in [
            "",
            "null",
            "{}",
            r#"{"op":"nope"}"#,
            r#"{"op":"verify_request"}"#,
            r#"{"op":"verify_request","signed":{},"now":1}"#,
            r#"{"op":"verify_request","signed":null,"now":-1}"#,
            r#"{"op":"sign_in_content","origin":"https://a.example","challenge":"ab","extra":1}"#,
        ] {
            let answer: Value = serde_json::from_str(&handle(input)).unwrap();
            assert_eq!(answer["ok"], false, "{input}");
            assert!(answer["error"].is_string(), "{input}");
        }
    }
}

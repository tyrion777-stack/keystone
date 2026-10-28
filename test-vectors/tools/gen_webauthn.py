"""Builds test-vectors/webauthn.json.

Usage: python3 -I gen_webauthn.py chrome_capture.json helper_capture.json > ../webauthn.json

chrome_capture.json comes from capture_webauthn.js (the raw browser API) and helper_capture.json
from capture_passkey_helper.js (js/keystone-passkey.js), both run against Chrome's virtual
authenticator. The other cases are signed here with OpenSSL (via the `cryptography` package),
independently of the Rust code that verifies them.
"""

import base64
import hashlib
import json
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # P-256 group order


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def wire(pub: ec.EllipticCurvePublicKey) -> str:
    return "p256:" + pub.public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex()


capture = json.load(open(sys.argv[1]))
cases = []

# --- Real Chrome output -------------------------------------------------------------------
real_expect = {"origin": capture["origin"], "rp_id": capture["rp_id"], "require_user_verification": True}
real_reg = capture["registration"]
real_author = wire(load_der_public_key(unb64u(real_reg["message"]["public_key"])))
cases.append({
    "name": "chrome_registration",
    "kind": "registration",
    "valid": True,
    "expect": {**real_expect, "challenge": real_reg["challenge"]},
    "message": real_reg["message"],
    "author": real_author,
    "sign_count": 1,
})
real_asn = capture["assertion"]
cases.append({
    "name": "chrome_assertion",
    "kind": "assertion",
    "valid": True,
    "expect": {**real_expect, "challenge": real_asn["challenge"]},
    "message": {"author": real_author, **real_asn["message"]},
    "sign_count": 2,
})
for name, field, value in [
    ("chrome_assertion_wrong_challenge", "challenge", b64u(bytes(32))),
    ("chrome_assertion_wrong_origin", "origin", "http://localhost:8766"),
    ("chrome_assertion_wrong_rp_id", "rp_id", "example.com"),
]:
    cases.append({
        "name": name,
        "kind": "assertion",
        "valid": False,
        "expect": {**real_expect, "challenge": real_asn["challenge"], field: value},
        "message": {"author": real_author, **real_asn["message"]},
    })

# --- Real Chrome output, through js/keystone-passkey.js ----------------------------------
helper = json.load(open(sys.argv[2]))
helper_expect = {"origin": helper["origin"], "rp_id": helper["rp_id"], "require_user_verification": True}
helper_author = wire(load_der_public_key(unb64u(helper["registration"]["message"]["public_key"])))


def count(msg):
    return int.from_bytes(unb64u(msg["authenticator_data"])[33:37], "big")


cases.append({
    "name": "helper_registration",
    "kind": "registration",
    "valid": True,
    "expect": {**helper_expect, "challenge": helper["registration"]["challenge"]},
    "message": helper["registration"]["message"],
    "author": helper_author,
    "sign_count": count(helper["registration"]["message"]),
})
for a in helper["assertions"]:
    cases.append({
        "name": f"helper_assertion_{a['name']}",
        "kind": "assertion",
        "valid": True,
        "expect": {**helper_expect, "challenge": a["challenge"]},
        "message": {"author": helper_author, **a["message"]},
        "sign_count": count(a["message"]),
    })

# --- Edge cases signed here --------------------------------------------------------------
key = ec.derive_private_key(int("0b" * 32, 16), ec.SECP256R1())
author = wire(key.public_key())
ORIGIN, RP_ID = "https://desk.example.com", "desk.example.com"
CHALLENGE = bytes(range(64, 96))
expect = {"challenge": b64u(CHALLENGE), "origin": ORIGIN, "rp_id": RP_ID, "require_user_verification": True}


def client_data(typ="webauthn.get", challenge=CHALLENGE, origin=ORIGIN, cross_origin=False):
    return json.dumps({"type": typ, "challenge": b64u(challenge), "origin": origin,
                       "crossOrigin": cross_origin}, separators=(",", ":")).encode()


def auth_data(flags=0x05, count=7, rp_id=RP_ID):
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + count.to_bytes(4, "big")


def assertion(ad, cd, high_s=None):
    der = key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    if high_s is not None:
        r, s = decode_dss_signature(der)
        low = min(s, N - s)
        der = encode_dss_signature(r, N - low if high_s else low)
    return {"author": author, "authenticator_data": b64u(ad), "client_data_json": b64u(cd),
            "signature": b64u(der)}


def case(name, valid, msg, expect_over=None, **extra):
    cases.append({"name": name, "kind": "assertion", "valid": valid,
                  "expect": {**expect, **(expect_over or {})}, "message": msg, **extra})


case("valid_user_verified", True, assertion(auth_data(), client_data(), high_s=False), sign_count=7)
case("valid_high_s", True, assertion(auth_data(), client_data(), high_s=True), sign_count=7,
     note="Authenticators do not normalise s; passkey signatures must accept both halves.")
case("presence_only_when_verification_required", False, assertion(auth_data(flags=0x01), client_data()))
case("presence_only_when_verification_optional", True, assertion(auth_data(flags=0x01), client_data()),
     {"require_user_verification": False}, sign_count=7)
case("no_user_presence", False, assertion(auth_data(flags=0x04), client_data()),
     {"require_user_verification": False})
case("registration_type_used_for_sign_in", False, assertion(auth_data(), client_data(typ="webauthn.create")))
case("cross_origin_iframe", False, assertion(auth_data(), client_data(cross_origin=True)))
case("signed_for_other_rp", False, assertion(auth_data(rp_id="other.example.com"), client_data()))

tampered = assertion(auth_data(), client_data())
ad = bytearray(unb64u(tampered["authenticator_data"]))
ad[36] ^= 1  # change the sign count after signing
tampered["authenticator_data"] = b64u(bytes(ad))
case("tampered_authenticator_data", False, tampered)

other = ec.generate_private_key(ec.SECP256R1())
case("signed_by_other_key", False, {**assertion(auth_data(), client_data()), "author": wire(other.public_key())})

case("ed25519_author", False, {**assertion(auth_data(), client_data()), "author": "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"},
     note="A valid Ed25519 key (from signed_message.json). Only P-256 passkeys for now.")

print(json.dumps({
    "description": "WebAuthn (passkey) verification vectors. chrome_* and helper_* cases are real output from Chrome's "
                   "virtual authenticator; the rest are signed with OpenSSL. Every implementation must agree "
                   "on `valid`, and on `sign_count` and `author` where given. Byte fields are base64url "
                   "without padding.",
    "cases": cases,
}, indent=2))

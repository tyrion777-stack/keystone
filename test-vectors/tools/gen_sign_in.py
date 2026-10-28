"""Builds test-vectors/sign_in.json, independently of the Rust code that verifies it.

Usage: python3 -I gen_sign_in.py > ../sign_in.json
Needs the `cryptography` and `blake3` packages (pip install blake3==1.0.0 cryptography).
"""

import json

import blake3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # P-256 group order
ORIGIN = "https://desk.example.com"
CHALLENGE = "c4" * 32

person = Ed25519PrivateKey.from_private_bytes(bytes([0x0D] * 32))
p256_person = ec.derive_private_key(int("10" * 32, 16), ec.SECP256R1())


def signed(key, content: str):
    """The SignedMessage rule: sign the UTF-8 bytes of the Blake3 hex of the content."""
    h = blake3.blake3(content.encode()).hexdigest()
    if isinstance(key, Ed25519PrivateKey):
        author = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        return {"author": author, "content": content, "content_hash": h,
                "signature": key.sign(h.encode()).hex()}
    r, s = decode_dss_signature(key.sign(h.encode(), ec.ECDSA(hashes.SHA256())))
    s = min(s, N - s)
    author = "p256:" + key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex()
    return {"author": author, "content": content, "content_hash": h,
            "signature": r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()}


def content(**over):
    c = {"kind": "keystone.signin", "v": 1, "origin": ORIGIN, "challenge": CHALLENGE}
    c.update(over)
    return json.dumps({k: v for k, v in c.items() if v is not None}, separators=(",", ":"))


cases = []


def case(name, valid, text, key=person, origin=ORIGIN, challenge=CHALLENGE, note=None):
    c = {"name": name, "valid": valid, "expected_origin": origin, "expected_challenge": challenge,
         "signed": signed(key, text)}
    if note:
        c["note"] = note
    cases.append(c)


case("valid", True, content(), note="sign_in_content(origin, challenge) must produce exactly this content.")
case("valid_p256_person", True, content(), key=p256_person)
case("valid_localhost", True, content(origin="http://localhost:5173"), origin="http://localhost:5173")
case("signed_on_another_site", False, content(origin="https://other.example.com"),
     note="The phishing case: a real challenge, signed on the wrong site.")
case("other_challenge", False, content(challenge="d5" * 32))
case("expected_origin_differs_only_by_slash", False, content(), origin=ORIGIN + "/")
case("wrong_kind", False, content(kind="keystone.approval"))
case("wrong_version", False, content(v=2))
case("unknown_field", False, content()[:-1] + ',"next":"/admin"}')
case("duplicate_origin", False, content(origin="https://other.example.com")[:-1] + ',"origin":"' + ORIGIN + '"}',
     note="A second origin must not override the first.")
case("missing_challenge", False, content(challenge=None))
case("challenge_uppercase", False, content(challenge=CHALLENGE.upper()), challenge=CHALLENGE.upper())
case("challenge_too_short", False, content(challenge="c4" * 15), challenge="c4" * 15)
case("origin_with_path", False, content(origin=ORIGIN + "/login"), origin=ORIGIN + "/login")
case("origin_http", False, content(origin="http://desk.example.com"), origin="http://desk.example.com")
case("not_json", False, CHALLENGE, note="A bare challenge, as signed before sign-in was bound to a site.")
case("v_as_string", False, content(v="1"))

tampered = signed(person, content())
tampered["content"] = content(origin="https://other.example.com")
cases.append({"name": "content_changed_after_signing", "valid": False, "expected_origin": "https://other.example.com",
              "expected_challenge": CHALLENGE, "signed": tampered})

print(json.dumps({
    "description": "Sign-in bound to a site (core/src/sign_in.rs). The browser signs "
                   "{kind:'keystone.signin',v:1,origin,challenge} with the SignedMessage rule; the "
                   "service accepts only its own origin and the challenge it issued. Every "
                   "implementation must agree on `valid` for every case.",
    "cases": cases,
}, indent=2))

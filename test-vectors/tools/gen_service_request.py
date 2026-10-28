"""Builds test-vectors/service_request.json, independently of the Rust code that verifies it.

Usage: python3 -I gen_service_request.py > ../service_request.json
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
NOW = 1_800_000_000

service = Ed25519PrivateKey.from_private_bytes(bytes([0x0C] * 32))
person = Ed25519PrivateKey.from_private_bytes(bytes([0x0D] * 32))
other_service = Ed25519PrivateKey.from_private_bytes(bytes([0x0E] * 32))
p256_service = ec.derive_private_key(int("0f" * 32, 16), ec.SECP256R1())


def ed_wire(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def signed(key, content: str):
    """The SignedMessage rule: sign the UTF-8 bytes of the Blake3 hex of the content."""
    h = blake3.blake3(content.encode()).hexdigest()
    if isinstance(key, Ed25519PrivateKey):
        return {"author": ed_wire(key), "content": content, "content_hash": h,
                "signature": key.sign(h.encode()).hex()}
    r, s = decode_dss_signature(key.sign(h.encode(), ec.ECDSA(hashes.SHA256())))
    s = min(s, N - s)
    author = "p256:" + key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex()
    return {"author": author, "content": content, "content_hash": h,
            "signature": r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()}


def request(**over):
    r = {"kind": "keystone.request", "v": 1, "service": "Front desk", "origin": "https://desk.example.com",
         "purpose": "check-in", "nonce": "a1" * 16, "issued_at": NOW - 10, "expires_at": NOW + 110}
    r.update(over)
    return {k: v for k, v in r.items() if v is not None}


def dumps(obj):
    return json.dumps(obj, separators=(",", ":"))


cases = []


def req_case(name, valid, content, key=service, note=None):
    c = {"name": name, "kind": "request", "valid": valid, "now": NOW, "signed": signed(key, content)}
    if note:
        c["note"] = note
    cases.append(c)


req_case("valid_check_in", True, dumps(request()))
req_case("valid_link", True, dumps(request(purpose="link")))
req_case("valid_sign", True, dumps(request(purpose="sign", payload="I confirm my address is unchanged.")))
req_case("valid_localhost_origin", True, dumps(request(origin="http://localhost:8765")))
req_case("valid_p256_service_key", True, dumps(request()), key=p256_service,
         note="A service may sign with a device key.")
req_case("valid_unicode_name", True, dumps({**request(), "service": "Réception"}))
req_case("valid_issued_within_clock_skew", True, dumps(request(issued_at=NOW + 30, expires_at=NOW + 150)))
req_case("valid_expired_within_clock_skew", True, dumps(request(issued_at=NOW - 200, expires_at=NOW - 30)))
req_case("expired", False, dumps(request(issued_at=NOW - 200, expires_at=NOW - 60)))
req_case("issued_in_the_future", False, dumps(request(issued_at=NOW + 61, expires_at=NOW + 180)))
req_case("lifetime_too_long", False, dumps(request(issued_at=NOW - 10, expires_at=NOW + 591)))
req_case("expires_before_issued", False, dumps(request(issued_at=NOW, expires_at=NOW)))
req_case("unknown_field", False, dumps({**request(), "redirect": "https://other.example.com"}))
req_case("duplicate_field", False, dumps(request())[:-1] + ',"purpose":"sign"}',
         note="A second purpose must not override the first.")
req_case("wrong_kind", False, dumps(request(kind="keystone.approval")))
req_case("wrong_version", False, dumps(request(v=2)))
req_case("unknown_purpose", False, dumps(request(purpose="pay")))
req_case("http_origin", False, dumps(request(origin="http://desk.example.com")))
req_case("origin_with_path", False, dumps(request(origin="https://desk.example.com/")))
req_case("origin_uppercase", False, dumps(request(origin="https://Desk.example.com")))
req_case("origin_with_user_info", False, dumps(request(origin="https://desk.example.com@other.example.com")))
req_case("origin_bad_port", False, dumps(request(origin="https://desk.example.com:99999")))
req_case("name_with_newline", False, dumps(request(service="Front desk\nVerified")))
req_case("name_with_direction_override", False, dumps(request(service="Front ‮ksed")),
         note="U+202E reverses the text after it on screen.")
req_case("name_too_long", False, dumps(request(service="F" * 65)))
req_case("name_with_outer_space", False, dumps(request(service=" Front desk")))
req_case("nonce_too_short", False, dumps(request(nonce="a1" * 15)))
req_case("nonce_uppercase", False, dumps(request(nonce="A1" * 16)))
req_case("sign_without_payload", False, dumps(request(purpose="sign")))
req_case("check_in_with_payload", False, dumps(request(payload="anything")))

tampered = signed(service, dumps(request()))
tampered["content"] = dumps(request(purpose="sign", payload="something else"))
cases.append({"name": "tampered_content", "kind": "request", "valid": False, "now": NOW, "signed": tampered})

# --- Approvals ----------------------------------------------------------------------------
issued = signed(service, dumps(request()))
other_issued = signed(service, dumps(request(nonce="b2" * 16)))


def approval(**over):
    a = {"kind": "keystone.approval", "v": 1, "request": issued["content_hash"],
         "service_key": issued["author"], "purpose": "check-in"}
    a.update(over)
    return dumps(a)


def appr_case(name, valid, content, issued_msg=issued, now=NOW, note=None):
    c = {"name": name, "kind": "approval", "valid": valid, "now": now, "issued": issued_msg,
         "approval": signed(person, content)}
    if valid:
        c["person"] = ed_wire(person)
    if note:
        c["note"] = note
    cases.append(c)


appr_case("approval_valid", True, approval())
appr_case("approval_for_other_request", False, approval(request=other_issued["content_hash"]))
appr_case("approval_for_other_purpose", False, approval(purpose="sign"))
appr_case("approval_for_other_service_key", False, approval(service_key=ed_wire(other_service)),
          note="An approval cannot be carried from one service to another.")
appr_case("approval_unknown_field", False, approval()[:-1] + ',"extra":1}')
appr_case("approval_wrong_kind", False, approval(kind="keystone.request"))
appr_case("approval_after_request_expired", False, approval(), now=NOW + 200)
bad_sig = {"name": "approval_bad_signature", "kind": "approval", "valid": False, "now": NOW, "issued": issued,
           "approval": signed(person, approval())}
bad_sig["approval"]["signature"] = signed(person, approval(purpose="link"))["signature"]
cases.append(bad_sig)

print(json.dumps({
    "description": "Signed service requests and approvals (stage 3). Signed with OpenSSL Ed25519/P-256 and "
                   "Python blake3, independently of the Rust verifier. `now` is the verifier's clock in unix "
                   "seconds. Every implementation must agree on `valid`, and on `person` where given.",
    "cases": cases,
}, indent=2, ensure_ascii=False))

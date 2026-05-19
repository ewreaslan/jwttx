import base64
import json
import hmac
import hashlib
import time
from typing import Optional


def b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt_split(token: str) -> tuple[str, str, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
    return parts[0], parts[1], parts[2]


def jwt_decode_header(token: str) -> dict:
    header_b64, _, _ = jwt_split(token)
    return json.loads(b64url_decode(header_b64))


def jwt_decode_payload(token: str) -> dict:
    _, payload_b64, _ = jwt_split(token)
    return json.loads(b64url_decode(payload_b64))


def jwt_build(header: dict, payload: dict, signature: bytes = b"") -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = b64url_encode(signature)
    return f"{h}.{p}.{s}"


def hs_sign(header: dict, payload: dict, secret: str, alg: str = "HS256") -> str:
    alg_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    if alg not in alg_map:
        raise ValueError(f"Unsupported HMAC algorithm: {alg}")
    header["alg"] = alg
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, alg_map[alg]).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def check_expiry(payload: dict) -> Optional[str]:
    now = int(time.time())
    if "exp" in payload:
        exp = payload["exp"]
        if exp < now:
            diff = now - exp
            return (
                f"[red]EXPIRED[/red] — {diff}s ago  "
                f"({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(exp))})"
            )
        diff = exp - now
        return (
            f"[green]VALID[/green] — expires in {diff}s  "
            f"({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(exp))})"
        )
    return None


def fix_expiry(payload: dict, extend_hours: int = 24) -> dict:
    import copy
    p = copy.deepcopy(payload)
    p["exp"] = int(time.time()) + (extend_hours * 3600)
    if "iat" in p:
        p["iat"] = int(time.time())
    if "nbf" in p:
        p["nbf"] = int(time.time())
    return p

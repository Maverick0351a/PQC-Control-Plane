import base64
import hashlib

def sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()

def content_digest_header_for(data: bytes) -> str:
    return f"sha-256=:{sha256_b64(data)}:"

def parse_content_digest(value: str) -> bytes:
    # expects: 'sha-256=:...:'
    if not value.startswith("sha-256=:") or not value.endswith(":"):
        raise ValueError("invalid Content-Digest format")
    b64 = value[len("sha-256=:"):-1]
    return base64.b64decode(b64.encode())

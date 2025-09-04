import base64

def parse_content_digest(header: str):
    # Expect sha-256=:base64:
    if not header or not header.startswith("sha-256=:") or not header.endswith(":"):
        raise ValueError("bad content-digest")
    b64 = header.split("=:",1)[1][:-1]
    return base64.b64decode(b64)

import hmac

def ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality for two byte strings (length must match)."""
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)

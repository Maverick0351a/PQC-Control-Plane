import redis
import base64
import os
from ..config import REDIS_URL

class NonceStore:
    def __init__(self):
        self.r = redis.from_url(REDIS_URL, decode_responses=True)

    def issue(self, route: str, client_ip: str, tls_id: str, ttl: int = 300) -> str:
        nonce = base64.b64encode(os.urandom(32)).decode()
        key = f"pch:{route}:{client_ip}:{tls_id}:{nonce}"
        self.r.set(key, "1", ex=ttl, nx=True)
        return nonce

    def consume(self, route: str, client_ip: str, tls_id: str, nonce: str) -> bool:
        key = f"pch:{route}:{client_ip}:{tls_id}:{nonce}"
        with self.r.pipeline() as p:
            p.delete(key)
            deleted, = p.execute()
        return deleted == 1

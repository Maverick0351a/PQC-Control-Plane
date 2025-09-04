import time
import threading
from typing import Tuple, Dict

class NonceStore:
    def __init__(self, ttl_seconds: int = 30):
        self.ttl = ttl_seconds
        self.lock = threading.Lock()
        self.store: Dict[Tuple[str,str,str,str], float] = {}

    def _key(self, route: str, client_ip: str, tls_id: str, nonce: str):
        return (route, client_ip, tls_id, nonce)

    def issue(self, route: str, client_ip: str, tls_id: str) -> str:
        nonce = __import__("base64").urlsafe_b64encode(__import__("os").urandom(24)).decode().rstrip("=")
        with self.lock:
            self.store[self._key(route, client_ip, tls_id, nonce)] = time.time() + self.ttl
        return nonce

    def consume(self, route: str, client_ip: str, tls_id: str, nonce: str) -> bool:
        k = self._key(route, client_ip, tls_id, nonce)
        now = time.time()
        with self.lock:
            exp = self.store.get(k)
            if not exp:
                return False
            if exp < now:
                del self.store[k]
                return False
            del self.store[k]
            return True

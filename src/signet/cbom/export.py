import datetime
import importlib.util
import json
from typing import Any, Dict
from ..config import BINDING_TYPE, ENFORCE_PCH_ROUTES, SERVER_SIGNING_KEY, CLIENT_KEYS

def _load_clients() -> Dict[str, Any]:
    try:
        with open(CLIENT_KEYS, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _libcrypto_version() -> str:
    try:
        from cryptography.hazmat.backends import default_backend  # type: ignore
        be = default_backend()
        ver = getattr(be, 'openssl_version_text', None)
        if callable(ver):  # pragma: no cover defensive
            ver = ver()
        return ver or 'unknown'
    except Exception:
        return 'unknown'

def _oqs_present() -> bool:
    return importlib.util.find_spec('oqs') is not None

def build_cbom() -> Dict[str, Any]:
    clients = _load_clients()
    components = [
        {"name": "ed25519", "type": "crypto-algorithm"},
        {"name": "sha-256", "type": "hash"},
        {"name": "merkle-tree", "type": "data-structure"},
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            # Use timezone-aware UTC timestamp per ISO 8601
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),
            "bindingType": BINDING_TYPE,
            "enforceRoutes": ENFORCE_PCH_ROUTES,
            "libcrypto": _libcrypto_version(),
            "oqs_present": _oqs_present(),
        },
        "components": components,
        "keys": {
            "server_signing_key": SERVER_SIGNING_KEY,
            "client_key_ids": list(clients.keys()),
        },
    }

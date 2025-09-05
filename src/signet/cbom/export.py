import datetime
import importlib.util
import json
import os
from typing import Any, Dict, List
from importlib import metadata
from ..config import (
    BINDING_TYPE,
    ENFORCE_PCH_ROUTES,
    SERVER_SIGNING_KEY,
    CLIENT_KEYS,
    BINDING_HEADER,
)

# Minimal dynamic CBOM (CycloneDX 1.5 JSON) export. Focused on runtime facts actually in use.

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

def _app_version() -> str:
    try:
        return metadata.version("signet-pqc")  # if packaged
    except Exception:
        # Fallback: derive from git or env; minimal placeholder
        return os.getenv("SIGNET_VERSION", "0.0.0-dev")


def _detect_crypto_components() -> List[Dict[str, Any]]:
    comps: List[Dict[str, Any]] = []
    # Core signature & hash primitives used in receipts & PCH challenges
    comps.append({
        "bom-ref": "alg-ed25519",
        "type": "library",
        "name": "ed25519",
        "properties": [{"name": "algorithm.primitive", "value": "sig"}],
    })
    comps.append({
        "bom-ref": "alg-sha-256",
        "type": "library",
        "name": "sha-256",
        "properties": [{"name": "algorithm.primitive", "value": "hash"}],
    })
    # Runtime crypto provider (OpenSSL via cryptography)
    comps.append({
        "bom-ref": "lib-cryptography",
        "type": "library",
        "name": "pyca-cryptography",
        "version": _libcrypto_version(),
    })
    if _oqs_present():
        comps.append({
            "bom-ref": "lib-oqs",
            "type": "library",
            "name": "liboqs (python-bindings)",
        })
    # Service facade component
    comps.append({
        "bom-ref": "svc-signet-api",
        "type": "service",
        "name": "signet-api",
    })
    return comps


def _cbom_extensions(clients: Dict[str, Any]) -> Dict[str, Any]:
    # algorithms extension: only primitives actively used now
    algorithms = [
        {
            "primitive": "sig",
            "name": "ed25519",
            "params": {"keySize": 256, "variant": "Ed25519"},
            "provider": {"name": "openssl", "version": _libcrypto_version()},
            "certification": {"fips": False},
        },
        {
            "primitive": "hash",
            "name": "sha-256",
            "params": {"outputSize": 256},
            "provider": {"name": "openssl", "version": _libcrypto_version()},
            "certification": {"fips": False},
        },
    ]
    # keys (only server STH signing key surfaced minimally)
    keys = [
        {
            "purpose": "sth_signing",
            "type": "ed25519",
            "keySize": 256,
            "lifecycle": "active",
        }
    ]
    # protocols (channel binding)
    protocols = [
        {"type": "tls", "version": "1.3", "binding": BINDING_TYPE}
    ]
    # http signature shape used by PCH
    http_sig = [
        {
            "sig_alg": "ed25519",
            "headers": ["@method", "@path", "content-digest", "pch-challenge", BINDING_HEADER.lower()],
        }
    ]
    return {
        "cbom:algorithms": algorithms,
        "cbom:keys": keys,
        "cbom:protocols": protocols,
        "cbom:http_sig": http_sig,
        "cbom:clients": list(clients.keys()),
    }


def build_cbom() -> Dict[str, Any]:
    clients = _load_clients()
    components = _detect_crypto_components()
    services = [
        {
            "bom-ref": "svc-protected-route",
            "name": "signet-protected-route",
            "endpoints": ["/protected", "/protected (POST)"],
        }
    ]
    extensions = _cbom_extensions(clients)
    bom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "component": {
                "bom-ref": "app-signet-pqc",
                "type": "application",
                "name": "signet-pqc",
                "version": _app_version(),
            },
            # Expose bindingType for tests and runtime introspection
            "bindingType": BINDING_TYPE,
            "enforceRoutes": ENFORCE_PCH_ROUTES,
        },
        "components": components,
        "services": services,
    "keys": {"client_key_ids": list(clients.keys())},
        "properties": [
            {"name": "binding.type", "value": BINDING_TYPE},
            {"name": "enforced.routes", "value": ",".join(ENFORCE_PCH_ROUTES) if ENFORCE_PCH_ROUTES else ""},
        ],
        "dependencies": [  # simple dependency edges (service depends on alg + library)
            {"ref": "svc-signet-api", "dependsOn": [c["bom-ref"] for c in components if c.get("bom-ref") and c["bom-ref"].startswith("alg-") or c["bom-ref"].startswith("lib-")]},
        ],
    }
    # Merge CBOM extension objects under top-level for simplicity (namespaced keys ok in JSON)
    bom.update(extensions)
    return bom


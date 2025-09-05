import datetime
import importlib.util
import json
import os
from typing import Any, Dict, List, Optional
from importlib import metadata
from ..config import (
    BINDING_TYPE,
    ENFORCE_PCH_ROUTES,
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

def _pkg_version(name: str) -> Optional[str]:
    try:
        return metadata.version(name)
    except Exception:
        return None

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
    # providers (crypto backends)
    providers = [
        {
            "bom-ref": "prov-openssl",
            "name": "OpenSSL",
            "version": _libcrypto_version(),
        }
    ]
    # loaded modules (python crypto bindings)
    modules = [
        {
            "bom-ref": "mod-pyca-cryptography",
            "name": "cryptography",
            "version": _pkg_version("cryptography") or "unknown",
        }
    ]
    if _oqs_present():
        modules.append({
            "bom-ref": "mod-liboqs",
            "name": "oqs",
            "version": _pkg_version("oqs") or "unknown",
        })
        providers.append({
            "bom-ref": "prov-liboqs",
            "name": "liboqs",
            "version": "unknown",
        })

    # algorithms extension: primitives in use with parameterSetIdentifier and provider refs
    algorithms = [
        {
            "bom-ref": "alg-ed25519",
            "primitive": "sig",
            "name": "ed25519",
            "parameterSetIdentifier": "Ed25519",
            "params": {"keySize": 256, "variant": "Ed25519"},
            "provider": {"ref": "prov-openssl"},
        },
        {
            "bom-ref": "alg-sha-256",
            "primitive": "hash",
            "name": "sha-256",
            "parameterSetIdentifier": "SHA-256",
            "params": {"outputSize": 256},
            "provider": {"ref": "prov-openssl"},
        },
        {
            "bom-ref": "alg-x25519",
            "primitive": "kex",
            "name": "x25519",
            "parameterSetIdentifier": "X25519",
            "provider": {"ref": "prov-openssl"},
        },
        {
            "bom-ref": "alg-aes-128-gcm",
            "primitive": "aead",
            "name": "aes-128-gcm",
            "parameterSetIdentifier": "AES-128-GCM",
            "provider": {"ref": "prov-openssl"},
        },
        {
            "bom-ref": "alg-aes-256-gcm",
            "primitive": "aead",
            "name": "aes-256-gcm",
            "parameterSetIdentifier": "AES-256-GCM",
            "provider": {"ref": "prov-openssl"},
        },
        {
            "bom-ref": "alg-chacha20-poly1305",
            "primitive": "aead",
            "name": "chacha20-poly1305",
            "parameterSetIdentifier": "CHACHA20-POLY1305",
            "provider": {"ref": "prov-openssl"},
        },
    ]
    # Optionally include a KEM for PQ experiments
    if any(p.get("bom-ref") == "prov-liboqs" for p in providers):
        algorithms.append({
            "bom-ref": "alg-ml-kem-512",
            "primitive": "kem",
            "name": "ml-kem",
            "parameterSetIdentifier": "ML-KEM-512",
            "provider": {"ref": "prov-liboqs"},
        })
    # keys (only server STH signing key surfaced minimally)
    keys = [
        {
            "purpose": "sth_signing",
            "type": "ed25519",
            "keySize": 256,
            "lifecycle": "active",
        }
    ]
    # protocols (channel binding) + active TLS 1.3 cipher suites
    protocols = [
        {
            "bom-ref": "proto-tls13-default",
            "type": "tls",
            "version": "1.3",
            "binding": BINDING_TYPE,
            "cipherSuites": [
                {
                    "bom-ref": "cs-tls-aes128gcm-sha256",
                    "ianaName": "TLS_AES_128_GCM_SHA256",
                    "kex": "x25519",
                    "sig": "ed25519",
                    "aead": "aes-128-gcm",
                    "hash": "sha-256",
                    "active": True,
                },
                {
                    "bom-ref": "cs-tls-chacha20poly1305-sha256",
                    "ianaName": "TLS_CHACHA20_POLY1305_SHA256",
                    "kex": "x25519",
                    "sig": "ed25519",
                    "aead": "chacha20-poly1305",
                    "hash": "sha-256",
                    "active": True,
                },
                {
                    "bom-ref": "cs-tls-aes256gcm-sha384",
                    "ianaName": "TLS_AES_256_GCM_SHA384",
                    "kex": "x25519",
                    "sig": "ed25519",
                    "aead": "aes-256-gcm",
                    "hash": "sha-384",
                    "active": True,
                },
            ],
        }
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
        "cbom:providers": providers,
        "cbom:modules": modules,
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
        "dependencies": [
            # Link protocol config to algorithms it relies on
            {"ref": "proto-tls13-default", "dependsOn": [a["bom-ref"] for a in extensions["cbom:algorithms"]]},
        ],
    }
    # Merge CBOM extension objects under top-level for simplicity (namespaced keys ok in JSON)
    bom.update(extensions)
    return bom


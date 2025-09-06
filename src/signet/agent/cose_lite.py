# Compatibility shim: expose the tiny COSE_Sign1 helpers under cose_lite
from .cose_tiny import Sign1, ed25519_sign, ed25519_verify  # re-export

import hashlib
from typing import List

def merkle_root(leaves: List[bytes]) -> bytes:
    if not leaves:
        return b"\x00" * 32
    layer = leaves
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i+1] if i+1 < len(layer) else left
            nxt.append(hashlib.sha256(left + right).digest())
        layer = nxt
    return layer[0]

def merkle_proof(leaves: List[bytes], index: int):
    path = []
    if index < 0 or index >= len(leaves):
        return path
    layer = leaves
    idx = index
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i+1] if i+1 < len(layer) else left
            if i == idx or i+1 == idx:
                if idx == i:
                    path.append(("R", (right)))
                else:
                    path.append(("L", (left)))
            nxt.append(hashlib.sha256(left + right).digest())
        layer = nxt
        idx //= 2
    import base64
    return [(d, base64.b64encode(sib).decode()) for d, sib in path]

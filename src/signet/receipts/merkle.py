import base64
import hashlib

def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return b"\x00" * 32
    nodes = [hashlib.sha256(leaf).digest() for leaf in leaves]
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i+1] if i+1 < len(nodes) else nodes[i]
            next_level.append(hashlib.sha256(left + right).digest())
        nodes = next_level
    return nodes[0]

def merkle_proof(leaves: list[bytes], index: int) -> list[tuple[str, str]]:
    # returns list of (dir, hash_b64)
    if index < 0 or index >= len(leaves):
        return []
    nodes = [hashlib.sha256(leaf).digest() for leaf in leaves]
    proof = []
    idx = index
    level = nodes
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1] if i+1 < len(level) else level[i]
            if i == idx - (idx % 2):
                if idx % 2 == 0:
                    # right sibling
                    proof.append(("R", base64.b64encode(right).decode()))
                else:
                    proof.append(("L", base64.b64encode(left).decode()))
            next_level.append(hashlib.sha256(left + right).digest())
        idx = idx // 2
        level = next_level
    return proof

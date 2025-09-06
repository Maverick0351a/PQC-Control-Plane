from __future__ import annotations

import base64
from pathlib import Path
import sys, os

# Allow running as a module without installing the package
sys.path.insert(0, os.path.abspath("src"))

from signet.vdc.pack import pack_vdc


def main() -> None:
    # Deterministic inputs
    meta = {
        1: "test",
        2: "signet-pqc-mvp",
        3: "2025-09-05T00:00:00Z",
        4: {1: "offline", 2: "suite"},
        5: {},
    }
    payloads = [("p1", "text/plain", b"VECTOR", "request")]
    priv = bytes(range(1, 33))
    kid = b"did:example:acme#v1"

    out_dir = Path("vectors/vdc")
    out_dir.mkdir(parents=True, exist_ok=True)

    def write(name: str, buf: bytes) -> None:
        (out_dir / f"{name}.vdc").write_bytes(buf)
        (out_dir / f"{name}.b16").write_text(buf.hex())
        (out_dir / f"{name}.b64").write_text(base64.b64encode(buf).decode())

    # Core
    core = pack_vdc(meta, payloads, priv, kid, attach_evg_anchor=False)
    write("core", core)

    # Bound (dummy EKM)
    ekm = b"E" * 32
    bound = pack_vdc(meta, payloads, priv, kid, attach_evg_anchor=False, ekm=ekm)
    write("bound_ekm", bound)

    # Anchored (toy CT/v2)
    anchored = pack_vdc(meta, payloads, priv, kid, attach_evg_anchor=True)
    write("anchored", anchored)

    # Negative – wrong digest: flip a byte in embedded payload
    bad = bytearray(core)
    bad[-1] ^= 0x01
    write("negative_tamper_payload", bytes(bad))


if __name__ == "__main__":
    main()

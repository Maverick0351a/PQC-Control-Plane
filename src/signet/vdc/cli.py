from __future__ import annotations

import argparse
import base64
from pathlib import Path

from .pack import pack_vdc
from .verify import verify_vdc


def cmd_pack(args: argparse.Namespace) -> int:
    # meta is provided via a minimal env: purpose, producer, created, crypto_context, policies
    meta = {
        1: args.purpose,
        2: args.producer,
        3: args.created,
        4: {1: args.protocol, 2: args.suite},
        5: {},
    }
    priv = base64.b64decode(args.priv_b64)
    kid = args.kid.encode()
    ekm = base64.b64decode(args.ekm_b64) if args.ekm_b64 else None
    buf = pack_vdc(
        meta,
        [("p1", args.cty, Path(args.input).read_bytes(), args.role)],
        priv,
        kid,
        attach_evg_anchor=args.anchor,
        ekm=ekm,
        profile=args.profile,
    )
    Path(args.output).write_bytes(buf)
    print(f"wrote {args.output} ({len(buf)} bytes)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    kid = args.kid.encode()
    pub = base64.b64decode(args.pub_b64)
    buf = Path(args.input).read_bytes()
    info = verify_vdc(buf, {"x": pub, "kid": kid})
    print({"ok": True, **info})
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser("vdc")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_pack = sub.add_parser("pack")
    p_pack.add_argument("--purpose", required=True)
    p_pack.add_argument("--producer", required=True)
    p_pack.add_argument("--created", required=True)
    p_pack.add_argument("--protocol", default="offline")
    p_pack.add_argument("--suite", default="TLS_AES_128_GCM_SHA256")
    p_pack.add_argument("--cty", default="text/plain")
    p_pack.add_argument("--role", default="request")
    p_pack.add_argument("--input", required=True)
    p_pack.add_argument("--output", required=True)
    p_pack.add_argument("--priv-b64", dest="priv_b64", required=True)
    p_pack.add_argument("--kid", required=True)
    p_pack.add_argument("--anchor", action="store_true")
    p_pack.add_argument("--ekm-b64", dest="ekm_b64")
    p_pack.add_argument("--profile", choices=["vdc-core", "vdc-bound", "vdc-anchored", "vdc-timestamped"], default=None)
    p_pack.set_defaults(func=cmd_pack)

    p_ver = sub.add_parser("verify")
    p_ver.add_argument("--input", required=True)
    p_ver.add_argument("--pub-b64", dest="pub_b64", required=True)
    p_ver.add_argument("--kid", required=True)
    p_ver.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

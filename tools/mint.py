#!/usr/bin/env python3
"""
mint.py — pure-Python cblicense short-code minter.

Byte-identical to the C `cbl-mint` CLI in tools/cbl_mint.c — same canonical
message, same HMAC-SHA-256, same Crockford-base32 truncation, same hyphen
formatting. Useful for vendor-portal / CI workflows that don't want to ship
a compiled binary.

Stdlib only — no external deps. Python 3.8+.

Usage:
    mint.py --family cbcontroller \\
            --device-id-b32 ABCDE-FGHIJ-... \\
            --salt-hex deadbeef...
    mint.py --family plc_firmware \\
            --device-id-hex 80a1f0... \\
            --salt-file vendor.salt   (reads 32 raw bytes OR 64 hex chars)

Env: CBL_SALT_HEX — fallback for --salt-hex.

The script also exposes the underlying primitives (`mint_short_code`,
`base32_encode`, `verify_short_code`) so other Python services can import
them directly without shelling out.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import sys
from typing import Iterable, Optional

# ---------------------------------------------------------------------------
# Constants — must match third_party/cblicense/include/cblicense/cblicense.h
# and the implementation in third_party/cblicense/src/cbl_core.c.
# ---------------------------------------------------------------------------
DEVICE_ID_LEN = 32
SALT_LEN = 32
SHORT_HMAC_BYTES = 10            # bytes of the HMAC tag we keep
SHORT_BARE_LEN = 15              # base32 chars in the formatted code
DOMAIN_PREFIX = b"cblicense\x00v1"  # "cblicense" + NUL + version tag

ENC_ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32

FAMILY_TO_BYTE = {
    "generic":      0x00,
    "cbcontroller": 0x01,
    "plc_firmware": 0x02,
    "hmi":          0x03,
    "cbmodules":    0x04,
}

# Decode-side ambiguity aliases (also matches cbl_base32.c).
_DECODE_ALIASES = {"I": "1", "L": "1", "O": "0"}


# ---------------------------------------------------------------------------
# Crockford base32 encode / decode (no Python stdlib equivalent — base64.b32
# uses RFC 4648 which has a different alphabet, so we roll our own).
# ---------------------------------------------------------------------------
def base32_encode(data: bytes) -> str:
    """Crockford-base32 encode `data` (5 bits per output char, MSB-first)."""
    out = []
    buf = 0
    bits = 0
    for byte in data:
        buf = (buf << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ENC_ALPHA[(buf >> bits) & 0x1F])
    if bits > 0:
        out.append(ENC_ALPHA[(buf << (5 - bits)) & 0x1F])
    return "".join(out)


def _normalize_b32(text: str) -> str:
    """Strip whitespace + hyphens, uppercase, apply I/L/O aliases."""
    s = []
    for ch in text:
        if ch in ("-", " ", "\t", "\r", "\n"):
            continue
        c = ch.upper()
        c = _DECODE_ALIASES.get(c, c)
        s.append(c)
    return "".join(s)


def base32_decode(text: str, *, expect_bits: Optional[int] = None) -> bytes:
    """Decode a Crockford-base32 string. Tolerant of hyphens / whitespace /
    the I/L/O ambiguity aliases. If `expect_bits` is given, validates exact
    length and rejects partial trailing bytes (matches cbl_base32.c)."""
    norm = _normalize_b32(text)
    out = bytearray()
    buf = 0
    bits = 0
    for ch in norm:
        idx = ENC_ALPHA.find(ch)
        if idx < 0:
            raise ValueError(f"invalid base32 character: {ch!r}")
        buf = (buf << 5) | idx
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    if expect_bits is not None:
        needed_chars = (expect_bits + 4) // 5            # ceil
        if len(norm) != needed_chars:
            raise ValueError(
                f"expected {needed_chars} base32 chars, got {len(norm)}",
            )
        if len(out) != expect_bits // 8:                 # floor
            raise ValueError(
                f"decoded {len(out)} bytes, expected {expect_bits // 8}",
            )
    return bytes(out)


# ---------------------------------------------------------------------------
# Mint + verify (mirror compute_short_tag/format_short_code in cbl_core.c).
# ---------------------------------------------------------------------------
def _family_byte(family: str) -> int:
    if family in FAMILY_TO_BYTE:
        return FAMILY_TO_BYTE[family]
    # Numeric fallback for downstream forks (matches the C CLI).
    try:
        v = int(family, 0)
    except (TypeError, ValueError):
        raise ValueError(f"unknown family: {family!r}")
    if not 0 <= v <= 255:
        raise ValueError(f"family byte out of range 0..255: {v}")
    return v


def _canonical_message(family: str, device_id: bytes) -> bytes:
    if len(device_id) != DEVICE_ID_LEN:
        raise ValueError(f"device_id must be {DEVICE_ID_LEN} bytes")
    return (
        DOMAIN_PREFIX
        + bytes([_family_byte(family)])
        + bytes([DEVICE_ID_LEN])
        + device_id
    )


def mint_short_code(family: str, device_id: bytes, salt: bytes) -> str:
    """Mint a 15-character Crockford-base32 short code for the given device,
    formatted as ``XXXXX-XXXXX-XXXXX``. Byte-identical to `cbl-mint`."""
    if len(salt) != SALT_LEN:
        raise ValueError(f"salt must be {SALT_LEN} bytes")
    msg = _canonical_message(family, device_id)
    tag = hmac.new(salt, msg, hashlib.sha256).digest()
    encoded = base32_encode(tag[:SHORT_HMAC_BYTES])
    bare = encoded[:SHORT_BARE_LEN]
    return f"{bare[:5]}-{bare[5:10]}-{bare[10:15]}"


def verify_short_code(
    user_typed: str, family: str, device_id: bytes, salt: bytes,
) -> bool:
    """Constant-time compare of a typed code against the expected code for
    this device + family + salt. Matches `cbl_verify_short_code` in C."""
    expected = mint_short_code(family, device_id, salt).replace("-", "")
    normalized = _normalize_b32(user_typed)
    if len(normalized) != SHORT_BARE_LEN:
        return False
    return hmac.compare_digest(expected.encode("ascii"), normalized.encode("ascii"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _read_salt(args: argparse.Namespace) -> bytes:
    raw_hex: Optional[str] = (
        args.salt_hex
        or os.environ.get("CBL_SALT_HEX")
    )
    if args.salt_file:
        with open(args.salt_file, "rb") as fh:
            data = fh.read()
        if len(data) == SALT_LEN:
            return data
        try:
            text = data.decode("ascii").strip()
        except UnicodeDecodeError:
            raise SystemExit(
                f"salt file must be either {SALT_LEN} raw bytes or "
                f"{SALT_LEN * 2} hex chars",
            )
        salt = bytes.fromhex(text)
        if len(salt) != SALT_LEN:
            raise SystemExit(
                f"salt-file hex must decode to exactly {SALT_LEN} bytes; "
                f"got {len(salt)}",
            )
        return salt
    if not raw_hex:
        raise SystemExit(
            "salt is required: pass --salt-hex / --salt-file, or set "
            "CBL_SALT_HEX in the env",
        )
    salt = bytes.fromhex(raw_hex.strip())
    if len(salt) != SALT_LEN:
        raise SystemExit(
            f"--salt-hex must be exactly {SALT_LEN * 2} hex chars; "
            f"got {len(raw_hex.strip())}",
        )
    return salt


def _read_device_id(args: argparse.Namespace) -> bytes:
    if args.device_id_b32:
        device_id = base32_decode(args.device_id_b32, expect_bits=DEVICE_ID_LEN * 8)
        return device_id
    if args.device_id_hex:
        clean = args.device_id_hex.replace(":", "").replace("-", "").strip()
        device_id = bytes.fromhex(clean)
        if len(device_id) != DEVICE_ID_LEN:
            raise SystemExit(
                f"--device-id-hex must decode to {DEVICE_ID_LEN} bytes; "
                f"got {len(device_id)}",
            )
        return device_id
    raise SystemExit("pass --device-id-b32 or --device-id-hex")


def _cmd_mint(args: argparse.Namespace) -> int:
    salt = _read_salt(args)
    device_id = _read_device_id(args)
    code = mint_short_code(args.family, device_id, salt)
    print(code)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    salt = _read_salt(args)
    device_id = _read_device_id(args)
    ok = verify_short_code(args.code, args.family, device_id, salt)
    if ok:
        print("ok")
        return 0
    print("verify failed", file=sys.stderr)
    return 1


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="mint.py",
        description="Pure-Python cblicense short-code minter / verifier "
        "(byte-identical to the C cbl-mint / cbl-verify CLIs).",
    )
    sub = ap.add_subparsers(dest="cmd", required=False)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--family", required=True,
        help="Product family: generic, cbcontroller, plc_firmware, hmi, "
        "cbmodules, or a 0..255 numeric byte for downstream forks",
    )
    did = common.add_mutually_exclusive_group(required=True)
    did.add_argument("--device-id-b32", help="Crockford-base32 device fingerprint")
    did.add_argument("--device-id-hex", help="Hex-encoded device fingerprint (64 chars)")
    salt = common.add_mutually_exclusive_group()
    salt.add_argument("--salt-hex", help="64 hex chars (32 bytes)")
    salt.add_argument("--salt-file", help="File containing the salt (raw 32 B or hex)")

    ap_mint = sub.add_parser("mint", parents=[common], help="Mint a short code")
    ap_mint.set_defaults(func=_cmd_mint)

    ap_verify = sub.add_parser(
        "verify", parents=[common], help="Verify a typed code",
    )
    ap_verify.add_argument("--code", required=True, help="The 15-char short code")
    ap_verify.set_defaults(func=_cmd_verify)

    # Default subcommand is `mint` for backward-compat with cbl-mint usage.
    ap.set_defaults(func=_cmd_mint)
    # Promote mint flags to the top-level parser too so `mint.py --family ...`
    # works without `mint.py mint --family ...`.
    for action in common._actions:
        if action.dest in ("help",) or any(
            existing.dest == action.dest for existing in ap._actions
        ):
            continue
        ap._add_action(action)
    return ap


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

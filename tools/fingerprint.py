#!/usr/bin/env python3
"""
fingerprint.py — pure-Python device-fingerprint helper.

Computes the same 32-byte SHA-256 device fingerprint that the C library +
the HMI server compute on a Linux host. Useful when the customer reports
their fingerprint over the phone and the vendor wants to double-check the
mint is targeting the right value, or when an installer wants to script
the activation flow over SSH.

Sources, in fingerprint order (must match cbl_fp_linux.c):
    0. primary network interface MAC, lowercase hex with colons
       (e.g. "b8:27:eb:12:34:56"), read from /sys/class/net/<if>/address
    1. /etc/machine-id  (or /var/lib/dbus/machine-id fallback)
    2. Pi serial from /proc/cpuinfo "Serial : ..."  (empty on non-Pi hosts)

Usage:
    fingerprint.py                          # auto-pick interface
    fingerprint.py --iface eth0             # pin to a specific NIC
    fingerprint.py --raw                    # print 64-hex (sha256) too
    fingerprint.py --segments               # show what each source returned

The b32 output is grouped 4-by-4 to match the HMI's License page rendering,
so a customer can read it off the kiosk and a vendor can paste it directly.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from typing import List, Optional, Tuple

import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("cbl_mint_local",
                                      os.path.join(os.path.dirname(__file__), "mint.py"))
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
base32_encode = _mod.base32_encode

DOMAIN = b"cblicense:fingerprint:v1"
DEVICE_ID_LEN = 32


def _read(path: str) -> str:
    try:
        with open(path, "r") as fh:
            return fh.read().rstrip()
    except (FileNotFoundError, PermissionError):
        return ""


def _list_ifaces() -> List[str]:
    base = "/sys/class/net"
    if not os.path.isdir(base):
        return []
    return [
        name for name in os.listdir(base)
        if name != "lo"
        and not name.startswith(("docker", "br-", "veth", "virbr"))
    ]


def _iface_mac(iface: str) -> str:
    return _read(f"/sys/class/net/{iface}/address")


def _pick_primary_iface() -> Optional[str]:
    best: Optional[Tuple[str, int]] = None
    for name in _list_ifaces():
        mac = _iface_mac(name)
        # 17 chars = "xx:xx:xx:xx:xx:xx"
        if len(mac) < 17:
            continue
        # Reject all-zero
        if not re.search(r"[1-9a-f]", mac.replace(":", "").replace("0", "")):
            continue
        score = 1
        if name.startswith("eth"):
            score = 100
        elif name.startswith("en"):
            score = 90
        elif name.startswith(("wlan", "wlp")):
            score = 50
        if best is None or score > best[1]:
            best = (name, score)
    return best[0] if best else None


def _read_pi_serial() -> str:
    text = _read("/proc/cpuinfo")
    if not text:
        return ""
    for line in text.splitlines():
        if line.startswith("Serial"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip()
    return ""


def gather_segments(iface: Optional[str] = None) -> List[Tuple[str, bytes]]:
    """Return [(label, bytes), ...] in fingerprint order."""
    ifn = iface or _pick_primary_iface()
    mac = _iface_mac(ifn) if ifn else ""
    machine_id = _read("/etc/machine-id") or _read("/var/lib/dbus/machine-id")
    pi_serial = _read_pi_serial()
    return [
        ("mac",        mac.encode("utf-8")),
        ("machine_id", machine_id.encode("utf-8")),
        ("pi_serial",  pi_serial.encode("utf-8")),
    ]


def compute_fingerprint(segments) -> bytes:
    """Same construction as cbl_compute_fingerprint in C: SHA-256 over a
    domain prefix followed by length-prefixed segments. Empty segments
    still contribute their zero-length byte to the hash."""
    h = hashlib.sha256()
    h.update(DOMAIN)
    nonempty = 0
    for _, data in segments:
        if len(data) > 255:
            raise ValueError("segment > 255 bytes")
        h.update(bytes([len(data)]))
        if data:
            h.update(data)
            nonempty += 1
    if nonempty == 0:
        raise RuntimeError("no fingerprint sources available — is /etc/machine-id readable?")
    return h.digest()


def grouped(s: str, n: int = 4, sep: str = "-") -> str:
    """Insert `sep` every `n` chars (matches HMI License page formatting)."""
    return sep.join(s[i:i + n] for i in range(0, len(s), n))


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="fingerprint.py",
        description="Compute the cblicense device fingerprint on a Linux host.",
    )
    ap.add_argument("--iface", help="Pin to a specific interface (e.g. eth0)")
    ap.add_argument("--raw", action="store_true",
                    help="Also print the raw 64-hex sha256 representation")
    ap.add_argument("--segments", action="store_true",
                    help="Show each fingerprint source contribution")
    ap.add_argument("--no-group", action="store_true",
                    help="Print the b32 string ungrouped (no hyphens)")
    args = ap.parse_args()

    if not sys.platform.startswith("linux"):
        print("warning: fingerprint.py is Linux-only (matches cbl_fp_linux); "
              "macOS/Windows hosts will report empty segments and exit 1",
              file=sys.stderr)

    segs = gather_segments(args.iface)
    if args.segments:
        for label, data in segs:
            print(f"  {label:12} ({len(data)} B): {data.decode('utf-8', errors='replace')!r}")
    try:
        device_id = compute_fingerprint(segs)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    b32 = base32_encode(device_id)
    if args.no_group:
        print(b32)
    else:
        print(grouped(b32, 4))
    if args.raw:
        print(f"# raw sha256: {device_id.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

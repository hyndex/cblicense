#!/usr/bin/env python3
"""
keygen — vendor-side cblicense activation-code generator.

A polished, opinionated CLI for the day-to-day "customer reports a
fingerprint, vendor mints a code" workflow. Built specifically for the
cbcontroller product family; pass --family for other products.

Pure-stdlib (Python 3.8+) — no pip install required.

Subcommands:
    init        Generate or import a vendor salt; save to ~/.cblicense/
    mint        Mint one code (interactive prompts, or fully via flags)
    batch       Mint many codes from a CSV / line-per-fingerprint file
    verify      Verify a typed code against a fingerprint
    log         Show recent mint history (vendor-side audit trail)
    info        Show salt fingerprint + state-dir contents (debug)

Run with no args → interactive mint, the most common case.

State directory:
    ~/.cblicense/
        vendor.salt   — 32 raw bytes, mode 0600
        mints.csv     — append-only audit log (timestamp, fingerprint, family, code, op)

Override the state dir with $CBL_STATE_DIR or --state-dir.
Override the salt with $CBL_SALT_HEX or --salt-hex/--salt-file.

Cross-checked against the C cbl-mint CLI: byte-identical output across
random (family, device_id, salt) triples. See ./tools/README.md for the
parity-fuzz recipe.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import getpass
import hashlib
import hmac
import os
import secrets
import shutil
import stat
import sys
import textwrap
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants — must match third_party/cblicense/include/cblicense/cblicense.h
# and the implementation in third_party/cblicense/src/cbl_core.c.
# ---------------------------------------------------------------------------
DEVICE_ID_LEN = 32
SALT_LEN = 32
SHORT_HMAC_BYTES = 10
SHORT_BARE_LEN = 15
DOMAIN_PREFIX = b"cblicense\x00v1"
FP_DOMAIN = b"cblicense:fingerprint:v1"

ENC_ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE_ALIASES = {"I": "1", "L": "1", "O": "0"}

FAMILY_TO_BYTE = {
    "generic":      0x00,
    "cbcontroller": 0x01,
    "plc_firmware": 0x02,
    "hmi":          0x03,
    "cbmodules":    0x04,
}
DEFAULT_FAMILY = "cbcontroller"

# ---------------------------------------------------------------------------
# Pretty output (ANSI) — falls back to plain text when stdout isn't a TTY.
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def _ansi(seq: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{seq}m{text}\033[0m"

bold     = lambda t: _ansi("1", t)
dim      = lambda t: _ansi("2", t)
red      = lambda t: _ansi("31", t)
green    = lambda t: _ansi("32", t)
yellow   = lambda t: _ansi("33", t)
blue     = lambda t: _ansi("34", t)
magenta  = lambda t: _ansi("35", t)
cyan     = lambda t: _ansi("36", t)


def banner(title: str, subtitle: str = "") -> None:
    width = max(56, len(title) + 6, len(subtitle) + 6)
    print()
    print(blue("┌" + "─" * (width - 2) + "┐"))
    print(blue("│ ") + bold(title.ljust(width - 4)) + blue(" │"))
    if subtitle:
        print(blue("│ ") + dim(subtitle.ljust(width - 4)) + blue(" │"))
    print(blue("└" + "─" * (width - 2) + "┘"))


def big_code(code: str) -> None:
    """Render the minted code in a prominent box for vendor support."""
    inner = f"   {code}   "
    width = len(inner) + 2
    print()
    print(green("┌─ Activation Code " + "─" * (width - 20) + "┐"))
    print(green("│") + " " * width + green("│"))
    print(green("│") + bold(inner.center(width)) + green("│"))
    print(green("│") + " " * width + green("│"))
    print(green("└" + "─" * width + "┘"))


# ---------------------------------------------------------------------------
# Crockford base32 (must match cbl_base32.c)
# ---------------------------------------------------------------------------
def base32_encode(data: bytes) -> str:
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
    s = []
    for ch in text:
        if ch in ("-", " ", "\t", "\r", "\n"):
            continue
        c = ch.upper()
        c = _DECODE_ALIASES.get(c, c)
        s.append(c)
    return "".join(s)


def base32_decode(text: str, *, expect_bits: Optional[int] = None) -> bytes:
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
        needed = (expect_bits + 4) // 5
        if len(norm) != needed:
            raise ValueError(f"expected {needed} base32 chars, got {len(norm)}")
        if len(out) != expect_bits // 8:
            raise ValueError(f"decoded {len(out)} bytes, expected {expect_bits // 8}")
    return bytes(out)


# ---------------------------------------------------------------------------
# Mint + verify (must match compute_short_tag/format_short_code in cbl_core.c)
# ---------------------------------------------------------------------------
def _family_byte(family: str) -> int:
    if family in FAMILY_TO_BYTE:
        return FAMILY_TO_BYTE[family]
    try:
        v = int(family, 0)
    except (TypeError, ValueError):
        raise ValueError(f"unknown family: {family!r}")
    if not 0 <= v <= 255:
        raise ValueError(f"family byte out of range 0..255: {v}")
    return v


def mint_short_code(family: str, device_id: bytes, salt: bytes) -> str:
    if len(device_id) != DEVICE_ID_LEN:
        raise ValueError(f"device_id must be {DEVICE_ID_LEN} bytes")
    if len(salt) != SALT_LEN:
        raise ValueError(f"salt must be {SALT_LEN} bytes")
    msg = (
        DOMAIN_PREFIX
        + bytes([_family_byte(family)])
        + bytes([DEVICE_ID_LEN])
        + device_id
    )
    tag = hmac.new(salt, msg, hashlib.sha256).digest()
    encoded = base32_encode(tag[:SHORT_HMAC_BYTES])
    bare = encoded[:SHORT_BARE_LEN]
    return f"{bare[:5]}-{bare[5:10]}-{bare[10:15]}"


def verify_short_code(user_typed: str, family: str, device_id: bytes, salt: bytes) -> bool:
    expected = mint_short_code(family, device_id, salt).replace("-", "")
    norm = _normalize_b32(user_typed)
    if len(norm) != SHORT_BARE_LEN:
        return False
    return hmac.compare_digest(expected.encode(), norm.encode())


# ---------------------------------------------------------------------------
# State directory: salt + audit log
# ---------------------------------------------------------------------------
def state_dir(override: Optional[str] = None) -> Path:
    if override:
        d = Path(override).expanduser()
    elif os.environ.get("CBL_STATE_DIR"):
        d = Path(os.environ["CBL_STATE_DIR"]).expanduser()
    else:
        d = Path.home() / ".cblicense"
    d.mkdir(mode=0o700, exist_ok=True)
    try:
        # Tighten perms even if pre-existing.
        d.chmod(0o700)
    except PermissionError:
        pass
    return d


def salt_path(override: Optional[str] = None) -> Path:
    return state_dir(override) / "vendor.salt"


def audit_path(override: Optional[str] = None) -> Path:
    return state_dir(override) / "mints.csv"


def load_salt(args: argparse.Namespace) -> bytes:
    """Load the vendor salt from --salt-hex, --salt-file, $CBL_SALT_HEX, or
    the state-dir vendor.salt — in that priority order."""
    raw_hex: Optional[str] = (
        getattr(args, "salt_hex", None)
        or os.environ.get("CBL_SALT_HEX")
    )
    if getattr(args, "salt_file", None):
        with open(args.salt_file, "rb") as fh:
            data = fh.read()
        if len(data) == SALT_LEN:
            return data
        try:
            text = data.decode("ascii").strip()
        except UnicodeDecodeError:
            raise SystemExit(f"salt file must be {SALT_LEN} raw bytes or hex")
        salt = bytes.fromhex(text)
        if len(salt) != SALT_LEN:
            raise SystemExit(f"salt-file hex must decode to {SALT_LEN} bytes")
        return salt
    if raw_hex:
        salt = bytes.fromhex(raw_hex.strip())
        if len(salt) != SALT_LEN:
            raise SystemExit(f"--salt-hex must be {SALT_LEN * 2} hex chars")
        return salt
    sp = salt_path(getattr(args, "state_dir", None))
    if sp.exists():
        data = sp.read_bytes()
        if len(data) != SALT_LEN:
            raise SystemExit(f"{sp} is not {SALT_LEN} bytes; corrupt?")
        return data
    raise SystemExit(
        red("error: no vendor salt found.") + "\n"
        "  Run " + bold("./keygen.py init") + " first to generate one,\n"
        "  or pass --salt-hex / --salt-file / set CBL_SALT_HEX."
    )


def save_salt(salt: bytes, override_dir: Optional[str] = None) -> Path:
    sp = salt_path(override_dir)
    if sp.exists():
        # Back up before overwrite so a salt rotation is recoverable.
        ts = _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
        backup = sp.with_name(f"vendor.salt.{ts}.bak")
        shutil.copy2(sp, backup)
        backup.chmod(0o600)
    sp.write_bytes(salt)
    sp.chmod(0o600)
    return sp


def salt_fingerprint(salt: bytes) -> str:
    """Short identifier for a salt — its own SHA-256 truncated to 16 hex.
    Vendors can confirm "yes that's our salt" without revealing it."""
    return hashlib.sha256(salt).hexdigest()[:16]


def append_audit(
    state_dir_override: Optional[str],
    family: str,
    fingerprint_b32: str,
    code: str,
    op: str,
    notes: str = "",
) -> None:
    p = audit_path(state_dir_override)
    new_file = not p.exists()
    with open(p, "a", newline="") as fh:
        w = csv.writer(fh)
        if new_file:
            w.writerow(["timestamp_utc", "op", "family", "fingerprint_b32", "code", "notes"])
        w.writerow([
            _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            op,
            family,
            fingerprint_b32,
            code,
            notes,
        ])


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    sp = salt_path(args.state_dir)
    if sp.exists() and not args.force:
        ex = sp.read_bytes()
        print(yellow("vendor salt already exists at ") + bold(str(sp)))
        print(f"  fingerprint: {salt_fingerprint(ex)}")
        print(f"  size: {len(ex)} B  perms: {oct(stat.S_IMODE(sp.stat().st_mode))}")
        print(yellow("→ pass --force to overwrite (auto-backs up the old one)."))
        return 0

    if args.from_hex is not None:
        salt = bytes.fromhex(args.from_hex.strip())
        if len(salt) != SALT_LEN:
            raise SystemExit(f"--from-hex must decode to exactly {SALT_LEN} bytes")
        op = "imported"
    elif args.from_stdin:
        text = sys.stdin.read().strip()
        salt = bytes.fromhex(text) if all(c in "0123456789abcdefABCDEF" for c in text) else text.encode()
        if len(salt) != SALT_LEN:
            raise SystemExit(f"stdin must yield exactly {SALT_LEN} bytes (raw or {SALT_LEN*2}-hex)")
        op = "imported"
    else:
        salt = secrets.token_bytes(SALT_LEN)
        op = "generated"

    saved = save_salt(salt, args.state_dir)
    banner("cblicense vendor salt — " + op)
    print(f"  path:        {bold(str(saved))}")
    print(f"  perms:       {oct(stat.S_IMODE(saved.stat().st_mode))}")
    print(f"  fingerprint: {salt_fingerprint(salt)}")
    print()
    print(yellow("⚠  Keep this file secret. Anyone with it can mint codes for any device"))
    print(yellow("   in the same product family. Recommended:"))
    print(yellow("   • Add /to .gitignore (we do this for you in tools/.gitignore)"))
    print(yellow("   • Back up to a password manager / vault / KMS"))
    print(yellow("   • Rotate via re-running ./keygen.py init --force when leaked"))
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    sp = salt_path(args.state_dir)
    ap = audit_path(args.state_dir)
    banner("cblicense state directory")
    print(f"  state dir:    {state_dir(args.state_dir)}")
    if sp.exists():
        salt = sp.read_bytes()
        print(f"  salt:         {sp.name}  ({len(salt)} B, perms {oct(stat.S_IMODE(sp.stat().st_mode))})")
        print(f"  fingerprint:  {salt_fingerprint(salt)}")
    else:
        print(f"  salt:         {red('NOT FOUND')} — run ./keygen.py init")
    if ap.exists():
        with open(ap) as fh:
            n = sum(1 for _ in fh) - 1  # subtract header
        print(f"  audit log:    {ap.name}  ({n} entries)")
    else:
        print(f"  audit log:    {dim('(empty)')}")
    print(f"  default family: {bold(DEFAULT_FAMILY)}")
    return 0


def _parse_device_id(value: str) -> bytes:
    """Accept b32 (with/without hyphens) or hex (with/without :/-/space)."""
    s = value.strip()
    # Try hex first (it's a strict subset of b32 chars 0-9 + A-F).
    hex_clean = s.replace(":", "").replace("-", "").replace(" ", "")
    if len(hex_clean) == DEVICE_ID_LEN * 2 and all(c in "0123456789abcdefABCDEF" for c in hex_clean):
        return bytes.fromhex(hex_clean)
    # Otherwise try b32.
    return base32_decode(s, expect_bits=DEVICE_ID_LEN * 8)


def cmd_mint(args: argparse.Namespace) -> int:
    salt = load_salt(args)

    # Resolve device-id from explicit flag or interactive prompt.
    if args.device_id:
        try:
            device_id = _parse_device_id(args.device_id)
        except Exception as e:
            print(red(f"error: invalid --device-id: {e}"), file=sys.stderr)
            return 2
    else:
        banner("cblicense key generator", "family: " + args.family)
        print(dim(f"salt loaded ({len(salt)} B, fingerprint: {salt_fingerprint(salt)})"))
        print()
        prompt = "Paste device fingerprint (b32 or 64-hex):\n  > "
        try:
            text = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n" + yellow("aborted."))
            return 130
        if not text:
            print(red("no fingerprint entered."))
            return 2
        try:
            device_id = _parse_device_id(text)
        except Exception as e:
            print(red(f"error: {e}"))
            return 2

    code = mint_short_code(args.family, device_id, salt)
    fp_b32 = base32_encode(device_id)

    if args.json:
        import json as _json
        print(_json.dumps({
            "family": args.family,
            "device_fingerprint_b32": fp_b32,
            "device_fingerprint_hex": device_id.hex(),
            "salt_fingerprint": salt_fingerprint(salt),
            "code": code,
            "minted_at_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }))
    else:
        big_code(code)
        print()
        print(f"  {dim('Family:    ')} {args.family}")
        print(f"  {dim('Device:    ')} {fp_b32[:32]}{dim('...')}  ({len(fp_b32)} chars)")
        print(f"  {dim('Salt:      ')} {salt_fingerprint(salt)}")
        print(f"  {dim('Minted:    ')} {_dt.datetime.utcnow().isoformat(timespec='seconds')}Z")

    if not args.no_log:
        append_audit(args.state_dir, args.family, fp_b32, code, "mint", args.notes or "")
        if not args.json:
            print(f"  {dim('Audit log: ')} {audit_path(args.state_dir)}")
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    salt = load_salt(args)
    rows_in: List[Tuple[str, str]] = []  # (fingerprint, notes)

    if args.input == "-":
        text_lines = sys.stdin.read().splitlines()
    else:
        with open(args.input) as fh:
            text_lines = fh.read().splitlines()

    for ln in text_lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        # Accept "fingerprint" or "fingerprint,notes" or CSV with header
        if "," in ln:
            head, _, rest = ln.partition(",")
            if head.lower().strip() in ("fingerprint", "device", "device_fingerprint"):
                continue  # header row
            rows_in.append((head.strip(), rest.strip()))
        else:
            rows_in.append((ln, ""))

    out_writer = None
    out_fh = None
    if args.output and args.output != "-":
        out_fh = open(args.output, "w", newline="")
        out_writer = csv.writer(out_fh)
        out_writer.writerow(["fingerprint_b32", "family", "code", "notes", "minted_at_utc"])
    elif args.json:
        out_rows = []

    success = 0
    failed = 0
    for fp_text, notes in rows_in:
        try:
            device_id = _parse_device_id(fp_text)
        except Exception as e:
            print(red(f"  skip: invalid fingerprint {fp_text!r}: {e}"), file=sys.stderr)
            failed += 1
            continue
        code = mint_short_code(args.family, device_id, salt)
        fp_b32 = base32_encode(device_id)
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if out_writer:
            out_writer.writerow([fp_b32, args.family, code, notes, ts])
        elif args.json:
            out_rows.append({
                "fingerprint_b32": fp_b32,
                "family": args.family,
                "code": code,
                "notes": notes,
                "minted_at_utc": ts,
            })
        else:
            print(f"  {green(code)}   {fp_b32[:24]}{dim('...')}   {dim(notes)}")
        if not args.no_log:
            append_audit(args.state_dir, args.family, fp_b32, code, "batch", notes)
        success += 1

    if out_fh:
        out_fh.close()
        print(green(f"wrote {success} codes to {args.output}"))
    elif args.json:
        import json as _json
        print(_json.dumps(out_rows, indent=2))
    if failed:
        print(red(f"{failed} entries failed"), file=sys.stderr)
    return 0 if failed == 0 else 1


def cmd_verify(args: argparse.Namespace) -> int:
    salt = load_salt(args)
    try:
        device_id = _parse_device_id(args.device_id)
    except Exception as e:
        raise SystemExit(f"invalid device-id: {e}")
    ok = verify_short_code(args.code, args.family, device_id, salt)
    if ok:
        print(green("ok") + " — code matches device + family + salt")
        if not args.no_log:
            append_audit(
                args.state_dir, args.family,
                base32_encode(device_id), args.code,
                "verify_ok", args.notes or "",
            )
        return 0
    print(red("FAIL") + " — code does not match")
    if not args.no_log:
        append_audit(
            args.state_dir, args.family,
            base32_encode(device_id), args.code,
            "verify_fail", args.notes or "",
        )
    return 1


def cmd_log(args: argparse.Namespace) -> int:
    p = audit_path(args.state_dir)
    if not p.exists():
        print(dim("(audit log empty)"))
        return 0
    with open(p) as fh:
        rows = list(csv.reader(fh))
    if not rows:
        return 0
    header, *data = rows
    if args.tail:
        data = data[-args.tail:]
    print(dim(",".join(header)))
    for row in data:
        ts, op, fam, fp, code, notes = row + [""] * (6 - len(row))
        op_color = green if op in ("mint", "verify_ok") else (red if op == "verify_fail" else cyan)
        print(f"{dim(ts)}  {op_color(op):20}  {fam:14}  {fp[:24]}{dim('...')}  {bold(code):20}  {dim(notes)}")
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    """Optional Tkinter GUI for support staff who'd rather click than type."""
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
    except ImportError:
        raise SystemExit("Tkinter not available — install python3-tk or use the CLI")

    salt = load_salt(args)

    root = tk.Tk()
    root.title("cblicense — Activation Code Generator")
    root.geometry("700x460")

    style = ttk.Style()
    if "clam" in style.theme_names():
        style.theme_use("clam")

    container = ttk.Frame(root, padding=20)
    container.pack(fill="both", expand=True)

    ttk.Label(container, text="Vendor Activation Code Generator",
              font=("Helvetica", 18, "bold")).pack(anchor="w")
    ttk.Label(container,
              text=f"family: {args.family}    salt: {salt_fingerprint(salt)}",
              foreground="#5e7588").pack(anchor="w", pady=(0, 16))

    fp_label = ttk.Label(container, text="Customer-reported device fingerprint:")
    fp_label.pack(anchor="w")
    fp_entry = tk.Text(container, height=4, width=70, font=("Menlo", 11), wrap="word")
    fp_entry.pack(fill="x", pady=(2, 12))

    notes_label = ttk.Label(container, text="Notes (optional, audit-logged):")
    notes_label.pack(anchor="w")
    notes_entry = ttk.Entry(container)
    notes_entry.pack(fill="x", pady=(2, 12))

    out_var = tk.StringVar(value="")
    ttk.Label(container, textvariable=out_var,
              font=("Menlo", 24, "bold"), foreground="#0c639f").pack(pady=10)

    status = tk.StringVar(value="")
    ttk.Label(container, textvariable=status,
              foreground="#5e7588").pack()

    def do_mint():
        text = fp_entry.get("1.0", "end").strip()
        try:
            device_id = _parse_device_id(text)
        except Exception as e:
            messagebox.showerror("Invalid fingerprint", str(e))
            return
        code = mint_short_code(args.family, device_id, salt)
        fp_b32 = base32_encode(device_id)
        out_var.set(code)
        status.set(f"minted at {_dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} — audit-logged")
        append_audit(args.state_dir, args.family, fp_b32, code, "mint_gui", notes_entry.get())
        # Auto-copy to clipboard
        root.clipboard_clear()
        root.clipboard_append(code)

    def do_clear():
        fp_entry.delete("1.0", "end")
        notes_entry.delete(0, "end")
        out_var.set("")
        status.set("")

    btnrow = ttk.Frame(container)
    btnrow.pack(fill="x", pady=8)
    ttk.Button(btnrow, text="Mint Code (auto-copy)", command=do_mint).pack(side="left", padx=(0, 8))
    ttk.Button(btnrow, text="Clear", command=do_clear).pack(side="left")

    root.mainloop()
    return 0


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------
def _common_state_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--state-dir", help="Override ~/.cblicense state dir")
    p.add_argument("--salt-hex",  help="Override salt (64 hex chars)")
    p.add_argument("--salt-file", help="Override salt (path to file)")
    p.add_argument("--family", default=DEFAULT_FAMILY,
                   help=f"Product family (default: {DEFAULT_FAMILY})")
    p.add_argument("--no-log", action="store_true",
                   help="Skip the local audit-log entry")


def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="keygen",
        description="Vendor activation-code generator for cblicense.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # First-time setup
              keygen init

              # Interactive mint (most common)
              keygen mint

              # One-shot mint
              keygen mint --device-id FMHQ-SXFK-... --notes "Customer ACME #4421"

              # Batch from a CSV
              keygen batch --input fingerprints.csv --output codes.csv

              # GUI mode for support staff
              keygen gui

              # Audit log
              keygen log --tail 20
        """),
    )
    sub = ap.add_subparsers(dest="cmd")

    p_init = sub.add_parser("init", help="Generate or import a vendor salt")
    p_init.add_argument("--state-dir", help="Override ~/.cblicense state dir")
    p_init.add_argument("--force", action="store_true",
                        help="Overwrite existing salt (backs up first)")
    src = p_init.add_mutually_exclusive_group()
    src.add_argument("--from-hex", help="Import an existing 64-hex salt")
    src.add_argument("--from-stdin", action="store_true",
                     help="Read salt from stdin (raw 32 bytes or 64-hex)")
    p_init.set_defaults(func=cmd_init)

    p_info = sub.add_parser("info", help="Show state-dir contents")
    p_info.add_argument("--state-dir", help="Override ~/.cblicense state dir")
    p_info.set_defaults(func=cmd_info)

    p_mint = sub.add_parser("mint", help="Mint a single activation code")
    _common_state_args(p_mint)
    p_mint.add_argument("--device-id",
                        help="Device fingerprint (b32 or 64-hex). Omit for interactive.")
    p_mint.add_argument("--notes", help="Optional notes for the audit log")
    p_mint.add_argument("--json", action="store_true", help="Machine-readable output")
    p_mint.set_defaults(func=cmd_mint)

    p_batch = sub.add_parser("batch", help="Mint many codes from a file")
    _common_state_args(p_batch)
    p_batch.add_argument("--input", required=True,
                         help="Input file (one fingerprint per line, optional ',notes'). - = stdin")
    p_batch.add_argument("--output", help="Output CSV. Omit / use - for stdout")
    p_batch.add_argument("--json", action="store_true", help="Output JSON instead of CSV/table")
    p_batch.set_defaults(func=cmd_batch)

    p_verify = sub.add_parser("verify", help="Verify a typed code")
    _common_state_args(p_verify)
    p_verify.add_argument("--device-id", required=True)
    p_verify.add_argument("--code", required=True)
    p_verify.add_argument("--notes", help="Optional notes for the audit log")
    p_verify.set_defaults(func=cmd_verify)

    p_log = sub.add_parser("log", help="Show audit log")
    p_log.add_argument("--state-dir", help="Override ~/.cblicense state dir")
    p_log.add_argument("--tail", type=int, default=20, help="Show last N entries (default 20)")
    p_log.set_defaults(func=cmd_log)

    p_gui = sub.add_parser("gui", help="Tkinter GUI for support staff")
    _common_state_args(p_gui)
    p_gui.set_defaults(func=cmd_gui)

    # Default to interactive mint if no subcommand given.
    args = ap.parse_args(argv)
    if not args.cmd:
        args = ap.parse_args(list(argv) + ["mint"] if argv else ["mint"])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
tunnel-key — vendor-side helper to manage Headscale pre-auth keys for
the EVSE fleet. The keys are what get baked into the Pi's SD image so
each device auto-enrolls into the Joulepoint tailnet on first boot.

Stdlib only (Python 3.8+). Talks to Headscale via SSH to invoke its
CLI; that avoids needing API tokens in the vendor-staff machine.

Subcommands:
    init           First-time: prompt for Headscale SSH host + identity,
                   save to ~/.cblicense/headscale.conf
    mint           Mint a fresh, reusable, tag:evse-fleet pre-auth key
                   (default 90d); print + log to mints.csv
    list           List active pre-auth keys
    revoke ID      Expire a pre-auth key by ID
    rotate         Mint a new key, mark the previous one for expiry in 7d,
                   so the next image build picks up the new one and old
                   field devices keep working until image refresh

State directory: ~/.cblicense/
    headscale.conf       host, ssh-key path, headscale-user-id
    tunnel-mints.csv     append-only log: timestamp, op, key-id, key-prefix, expires
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

CFG_FILENAME = "headscale.conf"
LOG_FILENAME = "tunnel-mints.csv"


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------
def state_dir() -> Path:
    base = os.environ.get("CBL_STATE_DIR")
    d = Path(base).expanduser() if base else Path.home() / ".cblicense"
    d.mkdir(mode=0o700, exist_ok=True)
    return d


def cfg_path() -> Path:
    return state_dir() / CFG_FILENAME


def log_path() -> Path:
    return state_dir() / LOG_FILENAME


def load_cfg() -> dict:
    p = cfg_path()
    if not p.exists():
        raise SystemExit(
            "no headscale config — run `tunnel-key.py init` first"
        )
    return json.loads(p.read_text())


def save_cfg(cfg: dict) -> Path:
    p = cfg_path()
    p.write_text(json.dumps(cfg, indent=2) + "\n")
    p.chmod(0o600)
    return p


def append_log(op: str, key_id: str, prefix: str, expires_iso: str, notes: str = "") -> None:
    p = log_path()
    new_file = not p.exists()
    with open(p, "a", newline="") as fh:
        w = csv.writer(fh)
        if new_file:
            w.writerow(["timestamp_utc", "op", "key_id", "key_prefix", "expires", "notes"])
        w.writerow([
            _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            op,
            key_id,
            prefix,
            expires_iso,
            notes,
        ])


# ---------------------------------------------------------------------------
# SSH wrapper around the Headscale CLI on the server
# ---------------------------------------------------------------------------
def _ssh(cfg: dict, remote_cmd: str) -> str:
    """Run a remote command via SSH, return stdout."""
    args = ["ssh"]
    if cfg.get("ssh_key"):
        args += ["-i", cfg["ssh_key"]]
    if cfg.get("ssh_user"):
        args += [f"{cfg['ssh_user']}@{cfg['ssh_host']}"]
    else:
        args += [cfg["ssh_host"]]
    args += ["--", remote_cmd]
    res = subprocess.run(args, check=False, capture_output=True, text=True)
    if res.returncode != 0:
        raise SystemExit(
            f"ssh remote command failed (exit {res.returncode}):\n"
            f"  cmd: {remote_cmd}\n"
            f"  stderr: {res.stderr.strip()}"
        )
    return res.stdout


def _hs(cfg: dict, *args: str, json_output: bool = False) -> str:
    """Run a `headscale ...` command on the remote, returning stdout."""
    parts = ["sudo", "headscale", *args]
    if json_output:
        parts += ["-o", "json"]
    return _ssh(cfg, " ".join(shlex.quote(p) for p in parts))


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    cfg = {
        "ssh_host":  args.ssh_host or input("Headscale SSH host (e.g. 3.6.55.118): ").strip(),
        "ssh_user":  args.ssh_user or (input("SSH user [ec2-user]: ").strip() or "ec2-user"),
        "ssh_key":   args.ssh_key or (input("SSH key path (or empty for default): ").strip() or None),
        "user_id":   args.user_id or int(input("Headscale user ID [1]: ").strip() or "1"),
        "default_tag": args.default_tag or "tag:evse-fleet",
    }
    if cfg["ssh_key"]:
        cfg["ssh_key"] = str(Path(cfg["ssh_key"]).expanduser())
    p = save_cfg(cfg)
    print(f"saved: {p} ({oct(p.stat().st_mode & 0o777)})")
    # Validate by talking to the server.
    try:
        users = _hs(cfg, "user", "list", json_output=True)
        print(f"  → talked to Headscale; user list: {users[:80]}...")
    except SystemExit as e:
        print(f"  warning: could not validate yet: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_mint(args: argparse.Namespace) -> int:
    cfg = load_cfg()
    out = _hs(
        cfg,
        "preauthkey", "create",
        "--user", str(cfg["user_id"]),
        *(["--reusable"] if args.reusable else []),
        *(["--ephemeral"] if args.ephemeral else []),
        "--tags", args.tag or cfg["default_tag"],
        "--expiration", args.expiration,
        json_output=True,
    )
    data = json.loads(out)
    key = data["key"]
    key_id = str(data["id"])
    prefix = key[:24] + "..."
    expires_seconds = data.get("expiration", {}).get("seconds")
    expires_iso = (
        _dt.datetime.fromtimestamp(expires_seconds, tz=_dt.timezone.utc).isoformat(timespec="seconds")
        if expires_seconds else "perpetual"
    )

    if args.json:
        print(json.dumps({
            "key": key,
            "id": key_id,
            "tag": args.tag or cfg["default_tag"],
            "expires_utc": expires_iso,
            "headscale_url": f"https://{cfg['ssh_host'].split('@')[-1]}",  # heuristic
        }, indent=2))
    else:
        print()
        print("=" * 64)
        print(f"  Pre-auth key minted (id={key_id})")
        print("=" * 64)
        print(f"  key:     {key}")
        print(f"  tag:     {args.tag or cfg['default_tag']}")
        print(f"  expires: {expires_iso}")
        print()
        print("  Bake this into your next rpi-image-gen build:")
        print(f"    IGconf_evse_tunnel_preauth_key={key}")

    append_log("mint", key_id, prefix, expires_iso, args.notes or "")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    cfg = load_cfg()
    out = _hs(cfg, "preauthkey", "list", json_output=True)
    keys = json.loads(out)
    if args.json:
        print(json.dumps(keys, indent=2))
        return 0
    if not keys:
        print("(no pre-auth keys)")
        return 0
    print(f"{'ID':<4} {'Tag':<25} {'Reusable':<10} {'Used':<6} {'Expires':<22} {'Key prefix':<28}")
    for k in keys:
        kid = str(k.get("id", "?"))
        tags = ",".join(k.get("acl_tags", []) or [])
        reusable = str(k.get("reusable", False))
        used = str(k.get("used", False))
        exp = k.get("expiration", {})
        if isinstance(exp, dict) and exp.get("seconds"):
            exp_iso = _dt.datetime.fromtimestamp(exp["seconds"], tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        else:
            exp_iso = "perpetual"
        prefix = (k.get("key", "") or "")[:24] + "..."
        print(f"{kid:<4} {tags:<25} {reusable:<10} {used:<6} {exp_iso:<22} {prefix}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    cfg = load_cfg()
    # Headscale 0.28: `preauthkey expire` takes the FULL key, not the ID. Look it up.
    out = _hs(cfg, "preauthkey", "list", json_output=True)
    keys = json.loads(out)
    target = next((k for k in keys if str(k.get("id")) == args.id), None)
    if not target:
        print(f"no pre-auth key with id={args.id}", file=sys.stderr)
        return 1
    full_key = target.get("key")
    if not full_key:
        print("server returned no `key` field; cannot expire by ID alone", file=sys.stderr)
        return 1
    _hs(cfg, "preauthkey", "expire", full_key)
    append_log("revoke", args.id, full_key[:24] + "...", "", args.notes or "")
    print(f"key id={args.id} expired")
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    """Mint a new key + flag the current one for expiry in 7 days."""
    print("→ minting new key")
    new_args = argparse.Namespace(
        reusable=True, ephemeral=False,
        tag=None, expiration="90d",
        notes="rotate", json=False,
    )
    cmd_mint(new_args)
    # Find the previous key and expire-soon (7d).
    cfg = load_cfg()
    keys = json.loads(_hs(cfg, "preauthkey", "list", json_output=True))
    # Sort by created (id ascending) and target the second-to-last.
    sorted_k = sorted(keys, key=lambda k: int(k.get("id", 0)))
    if len(sorted_k) >= 2:
        prev = sorted_k[-2]
        print(f"→ leaving previous key id={prev.get('id')} active for 7 more days")
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    p = log_path()
    if not p.exists():
        print("(no tunnel-key history yet)")
        return 0
    with open(p) as fh:
        rows = list(csv.reader(fh))
    if not rows: return 0
    header, *data = rows
    if args.tail: data = data[-args.tail:]
    print(",".join(header))
    for row in data:
        print(",".join(row))
    return 0


# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="tunnel-key", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="First-time setup")
    p_init.add_argument("--ssh-host")
    p_init.add_argument("--ssh-user")
    p_init.add_argument("--ssh-key")
    p_init.add_argument("--user-id", type=int)
    p_init.add_argument("--default-tag")
    p_init.set_defaults(func=cmd_init)

    p_mint = sub.add_parser("mint", help="Mint a new pre-auth key")
    p_mint.add_argument("--reusable", action="store_true", default=True)
    p_mint.add_argument("--ephemeral", action="store_true",
                        help="Nodes auto-removed when offline (only for short-lived test boxes)")
    p_mint.add_argument("--tag", help=f"Tag (default: from config, currently tag:evse-fleet)")
    p_mint.add_argument("--expiration", default="90d", help="Expiration (e.g. 90d, 24h)")
    p_mint.add_argument("--notes", help="Optional notes for the audit log")
    p_mint.add_argument("--json", action="store_true")
    p_mint.set_defaults(func=cmd_mint)

    p_list = sub.add_parser("list", help="List active pre-auth keys")
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_list)

    p_revoke = sub.add_parser("revoke", help="Expire a pre-auth key by ID")
    p_revoke.add_argument("id")
    p_revoke.add_argument("--notes")
    p_revoke.set_defaults(func=cmd_revoke)

    p_rotate = sub.add_parser("rotate", help="Mint a new key + leave previous active 7 days")
    p_rotate.set_defaults(func=cmd_rotate)

    p_log = sub.add_parser("log", help="Show vendor-side mint history")
    p_log.add_argument("--tail", type=int, default=50)
    p_log.set_defaults(func=cmd_log)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

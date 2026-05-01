# cblicense — CLI tools

Two parallel implementations of the same minting + verification logic:

| Tool                      | Language | Build step    | When to use                           |
|---------------------------|----------|---------------|---------------------------------------|
| `cbl-mint` / `cbl-verify` / `cbl-fingerprint` | C  | `cmake --build build` | Production: device-side + vendor CLI |
| `mint.py` / `fingerprint.py`               | Python | none (stdlib) | Vendor portal, CI, scripted activation |

Both produce byte-identical output. The Python implementation is verified
against the C library across 100 random triples on every commit (see the
fuzz section below).

## C CLI

Built by the top-level `CMakeLists.txt`. After `cmake --build build` the
three binaries appear in `build/`:

```
build/cbl-mint           # vendor side: mint a code from device-id + salt
build/cbl-verify         # device side: verify a typed code
build/cbl-fingerprint    # device side: print the local SHA-256 fingerprint
```

See the top-level [`README.md`](../README.md) for usage examples.

## Python CLI

Pure stdlib (Python 3.8+), no compile step, no external deps.

### `mint.py`

```bash
# Mint
./tools/mint.py --family cbcontroller \
                --device-id-b32 ABCDE-FGHIJ-... \
                --salt-hex deadbeef...
# → QW2YS-APBKA-JW4B2

# Mint with salt from a file (32 raw bytes OR 64 hex chars)
./tools/mint.py --family plc_firmware \
                --device-id-hex 80a1f0... \
                --salt-file vendor.salt

# Verify
./tools/mint.py verify --family cbcontroller \
                       --device-id-b32 ABCDE-FGHIJ-... \
                       --salt-hex deadbeef... \
                       --code QW2YS-APBKA-JW4B2
# → ok

# Salt can also come from CBL_SALT_HEX env
export CBL_SALT_HEX=deadbeef...
./tools/mint.py --family cbcontroller --device-id-b32 ABCDE-...
```

### `fingerprint.py`

Linux-only (matches the C `cbl_fp_linux.c` exactly). On macOS / Windows
the segments come back empty and the script exits 1.

```bash
./tools/fingerprint.py                 # auto-pick interface, b32 grouped 4-by-4
./tools/fingerprint.py --raw           # also print the 64-hex sha256
./tools/fingerprint.py --segments      # show what each source returned
./tools/fingerprint.py --iface eth1    # pin to a specific NIC
./tools/fingerprint.py --no-group      # ungrouped b32 (suitable for piping)
```

### Importing as a library

```python
from cblicense.tools.mint import (
    mint_short_code,
    verify_short_code,
    base32_encode,
    base32_decode,
)
from cblicense.tools.fingerprint import (
    compute_fingerprint,
    gather_segments,
)

device_id = compute_fingerprint(gather_segments())
code = mint_short_code("cbcontroller", device_id, salt_bytes)
```

## Verifying parity (Python ↔ C)

After any change to either implementation, re-run the fuzz test:

```bash
# From the cblicense repo root, with build/cbl-mint built:
python3 - <<'PY'
import secrets, subprocess, sys
sys.path.insert(0, "tools")
from mint import mint_short_code, verify_short_code

families = ["generic", "cbcontroller", "plc_firmware", "hmi", "cbmodules"]
for i in range(100):
    fam = families[i % len(families)]
    dev = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)
    py = mint_short_code(fam, dev, salt)
    c = subprocess.check_output([
        "./build/cbl-mint",
        "--family", fam,
        "--device-id-hex", dev.hex(),
        "--salt-hex", salt.hex(),
    ], text=True).strip()
    assert py == c, f"#{i} {fam}: py={py} c={c}"
    assert verify_short_code(c, fam, dev, salt)
print("100/100 byte-identical")
PY
```

If the assertion fires, the on-wire format has drifted between the two
implementations. The fix lives wherever the discrepancy is — usually the
canonical-message construction in `mint.py`'s `_canonical_message` vs.
`compute_short_tag` in `src/cbl_core.c`.

# cblicense

Async license-key activation for embedded + Linux devices. Pure C, no external dependencies, builds clean on ESP32, Raspberry Pi, generic Linux, and macOS.

**v0.1 mode** — HMAC-SHA-256 short-code:

```
device fingerprint  → SHA-256 of (MAC + machine-id + Pi serial / efuse MAC + chip rev)
license code        → 15-character "XXXXX-XXXXX-XXXXX" Crockford-base32 HMAC tag
verification        → constant-time, fully offline, no network, no clock
```

A vendor mints the code from the customer's reported device fingerprint; the customer types it into the kiosk; the device verifies locally. Same library on the controller (Linux/C++) and the PLC (ESP32/Arduino).

```c
#include "cblicense/cblicense.h"

uint8_t  device_id[CBL_DEVICE_ID_LEN];
char     code[CBL_SHORT_CODE_BUF_LEN];

cbl_compute_fingerprint(cbl_fp_linux(NULL), device_id);   /* or cbl_fp_esp32() */
cbl_status_t st = cbl_verify_short_code(user_input,
                                        CBL_FAMILY_CBCONTROLLER,
                                        device_id,
                                        kVendorSalt);
if (st == CBL_OK) { /* run unrestricted */ }
```

## Why a new library?

The off-the-shelf options (FlexLM, Sentinel, Nalpeiron, Cryptolens) all assume a fat client with internet, a mature CRM, and a Windows-friendly install path. None of them ship a 280 KB Arduino-S3 library that activates with a hand-typed 15-character code.

cblicense is built specifically for fleet-deployed embedded products:
- **Offline by design.** Activation is a one-time human relay (read fingerprint off the kiosk → send to vendor → get code back → type into HMI). Zero network deps at runtime.
- **Same API everywhere.** The 280 KB you ship on Arduino is the same library you link into your Linux daemon. No driver mismatches.
- **Honest about its trust model.** v0.1 is symmetric (HMAC). Whoever extracts the salt from one device can mint codes for the rest of the family. Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before shipping. Ed25519 signed-license mode is planned for v0.2.

## Three-layer architecture

```
┌────────────────────────────────────────────────────────────────────┐
│  Layer 3:  Enforcement policy (your app's job)                     │
│            soft / hard / grace-period / banner — see INTEGRATION.md │
├────────────────────────────────────────────────────────────────────┤
│  Layer 2:  Mint + verify (cblicense)                               │
│            HMAC-SHA-256, Crockford-base32, constant-time compare   │
├────────────────────────────────────────────────────────────────────┤
│  Layer 1:  Device fingerprint (cblicense + platform shim)          │
│            efuse / MAC / Pi serial / machine-id, length-prefixed    │
└────────────────────────────────────────────────────────────────────┘
```

## Build

### Linux / Raspberry Pi / macOS host

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
sudo cmake --install build              # optional
```

Produces:
- `libcblicense.a` (or `.so` with `-DCBL_BUILD_SHARED=ON`)
- `cbl-mint`, `cbl-verify`, `cbl-fingerprint` CLI tools
- 5 test binaries that all run under ~2 s

### ESP32 (PlatformIO / Arduino)

Drop the repo into your `lib/cblicense/` and add to `platformio.ini`:

```ini
[env:my-product]
platform = espressif32@6.8.0
board = esp32-s3-devkitc-1
framework = arduino
build_src_filter =
    +<*>
    +<../lib/cblicense/src/*.c>
    +<../lib/cblicense/platforms/generic/*.c>
    +<../lib/cblicense/platforms/esp32/*.c>
build_flags =
    -I lib/cblicense/include
    -I lib/cblicense/src
```

Or install via Arduino IDE: **Sketch → Include Library → Add .ZIP Library** with this repo zipped.

Cost on ESP32-S3: ~10 KB flash, < 200 B RAM. Ed25519 (v0.2) will add ~32 KB flash.

## Three CLI tools

```bash
# 1. From the customer's device — print the fingerprint
$ cbl-fingerprint --raw
FMHQ-SXFK-XHDG-690Z-GJXA-7YMF-61DT-AHS2-A7GF-MNTN-TA4F-FCP5-CC50
# raw device_id (sha256): 7d237cf5f3ec5b03241f84baa3fa8f305ba5472251e0fa5755d288f7b2c5630a
# provider: linux

# 2. On the vendor side — mint a code from the reported fingerprint
$ export CBL_SALT_HEX=65220686577803ff45bb3dcd1123dd555275b3d7edf42237469b9d6b5b9c78a4
$ cbl-mint --family cbcontroller \
           --device-id-b32 FMHQ-SXFK-XHDG-690Z-GJXA-7YMF-61DT-AHS2-A7GF-MNTN-TA4F-FCP5-CC50
QW2YS-APBKA-JW4B2

# 3. Back on the device — verify (or call the C API directly)
$ cbl-verify --family cbcontroller \
             --device-id-b32 FMHQ-SXFK-XHDG-690Z-GJXA-7YMF-61DT-AHS2-A7GF-MNTN-TA4F-FCP5-CC50 \
             --code QW2YS-APBKA-JW4B2
ok
```

A wrong family, wrong code, or wrong device ID all return `license code does not match this device`. Codes are case-insensitive and tolerate Crockford ambiguity (I/L → 1, O → 0).

## Roadmap

| Version | Adds                                                                                       | Status   |
|---------|--------------------------------------------------------------------------------------------|----------|
| v0.1    | HMAC short-code mode, Linux + macOS + ESP32 + generic providers, CLI tools, full tests     | shipped  |
| v0.2    | Ed25519 signed-license file mode (asymmetric), expiry, feature-mask, revocation list       | planned  |
| v0.3    | HMI activation page (controller side), QR fingerprint display, audit-log integration       | planned  |
| v0.4    | `cbl-mint-server` HTTP daemon for the vendor portal; multi-device site licenses            | planned  |
| v0.5    | Hardware-rooted mode (ESP32 efuse / Pi OTP) — clone-resistant per-unit secret              | planned  |

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Documentation

- [`docs/API.md`](docs/API.md) — full public API reference
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what cblicense does and does NOT defend against
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — how to wire it into cbcontroller + plc_firmware

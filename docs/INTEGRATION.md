# Integrating cblicense

A minimal recipe for both target platforms in this product family.

## cbcontroller (Linux/C++)

### 1. Add as a submodule or vendor directly

```bash
cd cbcontroller
git submodule add git@github.com:hyndex/cblicense.git third_party/cblicense
```

Or copy the `cblicense/` tree under `cbcontroller/third_party/`.

### 2. Hook into the existing CMake build

In `cbcontroller/CMakeLists.txt`:

```cmake
add_subdirectory(third_party/cblicense)
target_link_libraries(controllerd PRIVATE cblicense::cblicense)
```

### 3. Embed the vendor salt

Vendor salt should not live in the source tree. Generate once and ship via build-time injection:

```bash
# CI / release-bundle script
head -c 32 /dev/urandom > vendor.salt
xxd -i -n cbl_vendor_salt vendor.salt > generated/cbl_vendor_salt.h
```

Then in your code:

```c
#include "cblicense/cblicense.h"
#include "cbl_vendor_salt.h"   // produced by xxd, defines kCblVendorSalt

extern "C" const cbl_fingerprint_provider_t *cbl_fp_linux(const char *);

bool license_check_or_warn() {
    uint8_t device_id[CBL_DEVICE_ID_LEN];
    auto fp = cbl_fp_linux(nullptr);
    if (cbl_compute_fingerprint(fp, device_id) != CBL_OK) {
        log_err("license: cannot read device fingerprint");
        return false;
    }
    std::string code = read_license_code_from_disk();   // your impl
    cbl_status_t st = cbl_verify_short_code(
        code.c_str(), CBL_FAMILY_CBCONTROLLER, device_id, kCblVendorSalt);
    if (st != CBL_OK) {
        log_warn("license: %s", cbl_status_str(st));
        return false;
    }
    log_info("license: ACTIVE");
    return true;
}
```

### 4. Pick an enforcement policy

cblicense returns OK / not-OK; what to do with that is your job:

| Policy tier | Behavior on `not-OK` |
|-------------|-----------------------|
| Soft | Banner on HMI, full functionality, daily reminder, audit log |
| Medium | Banner + cap `siteLimitKW` to 50% of configured value |
| Hard | Refuse to start charging sessions; HMI still allows ops + support |
| Cliff | `exit(2)` from controllerd → systemd respawns + bangs into a restart loop |

Don't pick **Cliff** unless you really understand the field-service implications. Refusing to boot at 2 AM because a license file silently corrupted is not a good operator experience. Soft / Medium / Hard with a clear escalation timeline is better.

### 5. Wire the HMI activation page (optional, recommended)

The HMI-side route should:
1. On unlicensed boot, render a page showing the device fingerprint + a paste-in field.
2. POST the typed code to the controller.
3. Controller verifies; on OK, write `/opt/evse/license.code` and reload.

Wireframe:

```
┌────────────────────────────────────────┐
│ Device fingerprint                     │
│   FMHQ-SXFK-XHDG-690Z-GJXA-7YMF-...    │
│   [QR code]                            │
│                                        │
│ Send this fingerprint to support and   │
│ paste the activation code below:       │
│                                        │
│   [_____ _____ _____]                  │
│                                        │
│   [Activate]                           │
└────────────────────────────────────────┘
```

(v0.3 of cblicense will ship this page as a drop-in React component.)

## plc_firmware (ESP32 / Arduino)

### 1. Add as a PlatformIO library

In `plc_firmware/platformio.ini`:

```ini
[env:controller-plc1]
...
lib_deps =
    fastled/FastLED@^3.7.8
    ; cblicense as a local lib (path relative to project root)
    file://../cblicense

build_src_filter =
    +<*>
    +<../cblicense/src/*.c>
    +<../cblicense/platforms/generic/*.c>
    +<../cblicense/platforms/esp32/*.c>

build_flags =
    ...
    -I ../cblicense/include
    -I ../cblicense/src
```

(The PLC firmware already builds via PlatformIO; this just bolts on the library files.)

### 2. Inject the salt the same way

Same as Linux — keep the salt out of source. The PlatformIO `extra_script.py` is a fine place to write `generated/cbl_vendor_salt.h` from a CI secret env var.

### 3. Verify on boot

```cpp
extern "C" const cbl_fingerprint_provider_t *cbl_fp_esp32(void);

void license_setup() {
    uint8_t device_id[CBL_DEVICE_ID_LEN];
    if (cbl_compute_fingerprint(cbl_fp_esp32(), device_id) != CBL_OK) {
        Serial.println("[LICENSE] fingerprint failed");
        return;
    }
    char code[CBL_SHORT_CODE_BUF_LEN] = {0};
    nvs_get_str("license", code, sizeof(code));   // read from NVS
    if (code[0] == '\0') {
        Serial.println("[LICENSE] no code on file; awaiting setup-portal entry");
        // SW4 setup portal exposes the fingerprint + a code-entry field.
        return;
    }
    cbl_status_t st = cbl_verify_short_code(
        code, CBL_FAMILY_PLC_FIRMWARE, device_id, kCblVendorSalt);
    Serial.printf("[LICENSE] %s\n", cbl_status_str(st));
    g_license_active = (st == CBL_OK);
}
```

### 4. Reuse the existing SW4 setup portal

`plc_firmware` already has a captive-portal HTTP form for runtime config. Add two fields:
- read-only **device fingerprint** (run `cbl_encode_device_id`)
- writable **activation code** (15 chars + 2 hyphens)

The handler stores the code via `Preferences` and reboots.

## Operational checklist

- [ ] Generated and stored vendor salt in your secrets manager.
- [ ] Build pipeline injects salt at build time, not from git.
- [ ] Picked an enforcement policy (Soft / Medium / Hard).
- [ ] HMI shows the device fingerprint when no license is active.
- [ ] Audit-log every activation success + failure attempt.
- [ ] Documented the customer-side activation flow for support.
- [ ] Threat model reviewed (`docs/THREAT_MODEL.md`) and accepted as appropriate for this product tier.

## When to skip cblicense entirely

- You're shipping open-source firmware.
- Per-unit revenue is < the cost of one support call about license issues.
- You have a real DRM partner already integrated.
- Your customer's procurement process forbids any device-binding (some government / hospital deployments).

In all those cases, ship without it. cblicense is a tool, not a religion.

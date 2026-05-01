# cblicense API reference (v0.1)

All public symbols live in `cblicense/cblicense.h`. The library is C11 with `extern "C"` guards so it links cleanly into both C and C++ projects.

## Constants

| Macro | Value | Meaning |
|-------|-------|---------|
| `CBL_DEVICE_ID_LEN` | 32 | bytes in canonical device fingerprint (SHA-256 output) |
| `CBL_SALT_LEN` | 32 | bytes in vendor salt (HMAC-SHA-256 key) |
| `CBL_SHORT_CODE_BARE_LEN` | 15 | base32 chars in short code, no hyphens |
| `CBL_SHORT_CODE_FORMAT_LEN` | 17 | with hyphens at positions 5 and 11 |
| `CBL_SHORT_CODE_BUF_LEN` | 18 | with hyphens + trailing NUL |
| `CBL_DEVICE_ID_STR_LEN` | 52 | base32-encoded device-id length, no NUL |
| `CBL_DEVICE_ID_STR_BUF_LEN` | 53 | with NUL |

## Types

### `cbl_status_t`
Return value of every function. Negative = error, 0 = OK.

```c
typedef enum {
    CBL_OK                   = 0,
    CBL_ERR_INVALID_ARG      = -1,
    CBL_ERR_BUFFER_TOO_SMALL = -2,
    CBL_ERR_BAD_FORMAT       = -3,
    CBL_ERR_DEVICE_MISMATCH  = -4,
    CBL_ERR_EXPIRED          = -5,   // (reserved for v0.2)
    CBL_ERR_BAD_FAMILY       = -6,   // (reserved for v0.2)
    CBL_ERR_BAD_VERSION      = -7,   // (reserved for v0.2)
    CBL_ERR_PLATFORM         = -8,
    CBL_ERR_INTERNAL         = -9,
} cbl_status_t;
```

### `cbl_family_t`
Product family identifier. Values 0x00-0x7F reserved for upstream cblicense; 0x80-0xFF for downstream forks / OEMs.

```c
CBL_FAMILY_GENERIC      = 0x00
CBL_FAMILY_CBCONTROLLER = 0x01
CBL_FAMILY_PLC_FIRMWARE = 0x02
CBL_FAMILY_HMI          = 0x03
CBL_FAMILY_CBMODULES    = 0x04
CBL_FAMILY_USER_BASE    = 0x80
```

### `cbl_fingerprint_provider_t`
Interface that platform shims implement. Library calls `read_segment(ctx, index, buf, cap, &len)` for `index = 0, 1, 2, …` until it returns `CBL_ERR_INVALID_ARG` (= no more segments).

```c
typedef struct cbl_fingerprint_provider {
    cbl_status_t (*read_segment)(void *ctx, uint32_t index,
                                 uint8_t *out, size_t out_capacity,
                                 size_t *out_len);
    void *ctx;
    const char *name;
} cbl_fingerprint_provider_t;
```

## Functions

### `cbl_compute_fingerprint(fp, out_device_id)`
Walks the provider's segments, length-prefixing each into a SHA-256 stream domain-separated by `"cblicense:fingerprint:v1"`. Output is a 32-byte canonical device ID.

Returns `CBL_OK`, or `CBL_ERR_PLATFORM` if no segments yielded data.

### `cbl_encode_device_id(device_id, out, out_capacity)`
Crockford-base32 encode 32 bytes → 52-character string. `out_capacity` must be ≥ 53 to include the trailing NUL.

### `cbl_mint_short_code(family, device_id, salt, out_code)`
Vendor-side. Computes HMAC-SHA-256 over a domain-prefixed canonical message, base32-encodes the first 10 bytes, formats as `"XXXXX-XXXXX-XXXXX"`. `out_code` must point to a `CBL_SHORT_CODE_BUF_LEN`-byte buffer.

### `cbl_verify_short_code(user_typed, family, device_id, salt)`
Device-side. Normalizes the input (strips hyphens / whitespace, uppercase, Crockford ambiguity aliases), recomputes the expected code locally, and compares in constant time.

Returns:
- `CBL_OK` — code matches
- `CBL_ERR_INVALID_ARG` — `user_typed`, `device_id`, or `salt` was NULL
- `CBL_ERR_BAD_FORMAT` — input has the wrong number of base32 chars or invalid characters
- `CBL_ERR_DEVICE_MISMATCH` — input is well-formed but doesn't match this device + family + salt

### `cbl_const_time_eq(a, b, len)`
Branchless constant-time byte compare. Returns 1 on equality, 0 otherwise. Use this for any license-related compare in your own code; never use `memcmp()`.

### `cbl_status_str(status)`
Returns a non-NULL human-readable string for any status code.

### `cbl_version_str(void)`
Returns the build-time library version string (e.g. `"cblicense/0.1.0"`).

## Platform fingerprint providers

Platform shims live under `platforms/<os>/` and expose a single accessor:

```c
const cbl_fingerprint_provider_t *cbl_fp_linux(const char *iface_or_NULL);
const cbl_fingerprint_provider_t *cbl_fp_macos(const char *iface_or_NULL);
const cbl_fingerprint_provider_t *cbl_fp_esp32(void);
const cbl_fingerprint_provider_t *cbl_fp_generic_init(cbl_fp_generic_ctx_t *ctx,
                                                      const uint8_t *data, size_t len);
```

The pointers returned by `cbl_fp_linux` / `cbl_fp_macos` / `cbl_fp_esp32` are static; lifetime is the entire process. The generic provider stores its state in a caller-owned context struct.

## What's not in v0.1

| Feature | Plan |
|---------|------|
| License expiry | v0.2 (signed-license files) |
| Feature flags / tier mask | v0.2 |
| Revocation list | v0.4 |
| Hardware-rooted secret | v0.5 (ESP32 efuse / Pi OTP) |
| Asymmetric (Ed25519) keys | v0.2 |

## Type forward-compatibility

The `cbl_payload_t` struct is exposed in `cblicense.h` but only used internally in v0.1. v0.2 will add `cbl_mint_signed_license` / `cbl_verify_signed_license` that take it; you can build against the field shape today.

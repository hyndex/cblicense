/*
 * cblicense — async license-key activation for embedded + Linux devices.
 *
 * v0.1: HMAC-SHA-256 short-code mode.
 *   - 15 Crockford-base32 characters, formatted as "XXXXX-XXXXX-XXXXX"
 *   - bound to a SHA-256 device fingerprint composed from non-spoofable
 *     hardware sources (efuse MAC on ESP32; eth0 MAC + Pi serial +
 *     /etc/machine-id on Linux/Pi; user-supplied bytes on generic).
 *   - HMAC keyed by a 32-byte salt baked into the firmware; whoever has
 *     the salt can mint codes for any device — see THREAT_MODEL.md.
 *
 * v0.2 (planned): Ed25519 signed-license file mode for tiered SKUs,
 *   expiry, feature flags, and revocation. The cbl_payload_t type below
 *   is already shaped to carry the full payload so the v0.1 short-code
 *   path is forward-compatible.
 *
 * The library is pure C11, dependency-free, and links cleanly into both
 * cbcontroller (Linux/C++) and plc_firmware (ESP32/Arduino-S3). All hot
 * paths are constant-time and never allocate.
 */

#ifndef CBLICENSE_H
#define CBLICENSE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CBLICENSE_VERSION_MAJOR 0
#define CBLICENSE_VERSION_MINOR 1
#define CBLICENSE_VERSION_PATCH 0

/* -------------------------------------------------------------------------- */
/* Status codes — all cbl_* functions return one of these. 0 = success.       */
/* -------------------------------------------------------------------------- */
typedef enum {
    CBL_OK                   = 0,
    CBL_ERR_INVALID_ARG      = -1,
    CBL_ERR_BUFFER_TOO_SMALL = -2,
    CBL_ERR_BAD_FORMAT       = -3,   /* malformed user input (not enough chars, bad chars) */
    CBL_ERR_DEVICE_MISMATCH  = -4,   /* code is well-formed but doesn't match this device */
    CBL_ERR_EXPIRED          = -5,   /* license payload past expiry (signed-license mode only) */
    CBL_ERR_BAD_FAMILY       = -6,   /* code was minted for a different product family */
    CBL_ERR_BAD_VERSION      = -7,   /* payload version newer than this lib understands */
    CBL_ERR_PLATFORM         = -8,   /* fingerprint provider failed to read sources */
    CBL_ERR_INTERNAL         = -9,
} cbl_status_t;

/* Human-readable status string. Always returns a non-NULL pointer. */
const char *cbl_status_str(cbl_status_t status);

/* Library version string (e.g. "cblicense/0.1.0"). */
const char *cbl_version_str(void);

/* -------------------------------------------------------------------------- */
/* Product family identifiers.                                                */
/*                                                                            */
/* The family byte is mixed into the HMAC input so a code minted for          */
/* CBL_FAMILY_CBCONTROLLER won't validate when typed into a PLC, even with    */
/* the same vendor salt. This lets you charge per-product separately.         */
/* Values >= 0x80 are reserved for downstream forks / OEMs.                   */
/* -------------------------------------------------------------------------- */
typedef enum {
    CBL_FAMILY_GENERIC      = 0x00,
    CBL_FAMILY_CBCONTROLLER = 0x01,
    CBL_FAMILY_PLC_FIRMWARE = 0x02,
    CBL_FAMILY_HMI          = 0x03,
    CBL_FAMILY_CBMODULES    = 0x04,
    CBL_FAMILY_USER_BASE    = 0x80,
} cbl_family_t;

/* -------------------------------------------------------------------------- */
/* Sizes / lengths.                                                           */
/* -------------------------------------------------------------------------- */
#define CBL_DEVICE_ID_LEN          32u   /* SHA-256 of fingerprint sources */
#define CBL_SALT_LEN               32u   /* HMAC-SHA-256 key */

/* Short-code geometry: 15 base32 chars = 75 bits of HMAC truncation. */
#define CBL_SHORT_CODE_BARE_LEN    15u
#define CBL_SHORT_CODE_FORMAT_LEN  17u   /* "XXXXX-XXXXX-XXXXX" */
#define CBL_SHORT_CODE_BUF_LEN     18u   /* + NUL */

/* Encoded device-id string length (Crockford-base32 of 32 bytes = 52 chars). */
#define CBL_DEVICE_ID_STR_LEN      52u
#define CBL_DEVICE_ID_STR_BUF_LEN  53u

/* -------------------------------------------------------------------------- */
/* Fingerprint provider — composes the canonical 32-byte device ID from       */
/* one or more platform-specific sources.                                     */
/*                                                                            */
/*   read_segment(ctx, index, out, out_capacity, out_len)                     */
/*     - called repeatedly for index = 0, 1, 2, ...                           */
/*     - returns CBL_OK and writes the segment bytes if available             */
/*     - returns CBL_ERR_INVALID_ARG when index is past the last segment      */
/*       (this is the loop-termination signal, not a "real" error)            */
/*     - returns CBL_ERR_PLATFORM if a source the platform expected to be     */
/*       present is missing (e.g. /etc/machine-id unreadable)                 */
/*                                                                            */
/* Each segment is hashed in order into the SHA-256 state, with a 1-byte      */
/* length prefix so concatenation is unambiguous. The order matters and is    */
/* part of the on-wire format.                                                */
/*                                                                            */
/* See platforms/<os>/cbl_fp_<os>.c for ready-made implementations.           */
/* -------------------------------------------------------------------------- */
typedef struct cbl_fingerprint_provider {
    cbl_status_t (*read_segment)(void *ctx,
                                 uint32_t index,
                                 uint8_t *out,
                                 size_t out_capacity,
                                 size_t *out_len);
    void *ctx;
    const char *name;  /* short, human-readable; for diagnostics + audit logs */
} cbl_fingerprint_provider_t;

/* Compute the 32-byte canonical device ID from a fingerprint provider.
 * Returns CBL_OK on success. The provider must yield at least one segment;
 * an empty provider returns CBL_ERR_PLATFORM. */
cbl_status_t cbl_compute_fingerprint(const cbl_fingerprint_provider_t *fp,
                                     uint8_t out_device_id[CBL_DEVICE_ID_LEN]);

/* Encode the device ID as a printable Crockford-base32 string for support
 * tickets, HMI activation pages, and audit logs. Output is uppercase. */
cbl_status_t cbl_encode_device_id(const uint8_t device_id[CBL_DEVICE_ID_LEN],
                                  char *out, size_t out_capacity);

/* -------------------------------------------------------------------------- */
/* v0.1 short-code API.                                                       */
/*                                                                            */
/* Vendor side — mint a code from family + device fingerprint + salt.         */
/* Device side — verify a typed code against the same three values.           */
/*                                                                            */
/* Both functions are pure (no allocation, no I/O, no clock). They never      */
/* leak the salt or HMAC by timing — verification uses a constant-time        */
/* compare regardless of where the user input diverges from the expected.     */
/* -------------------------------------------------------------------------- */
cbl_status_t cbl_mint_short_code(cbl_family_t family,
                                 const uint8_t device_id[CBL_DEVICE_ID_LEN],
                                 const uint8_t salt[CBL_SALT_LEN],
                                 char out_code[CBL_SHORT_CODE_BUF_LEN]);

cbl_status_t cbl_verify_short_code(const char *user_typed,
                                   cbl_family_t family,
                                   const uint8_t device_id[CBL_DEVICE_ID_LEN],
                                   const uint8_t salt[CBL_SALT_LEN]);

/* -------------------------------------------------------------------------- */
/* Forward-compatible payload type.                                           */
/*                                                                            */
/* v0.1 short-code mode encodes only family + device_id + salt. v0.2 will     */
/* add expiry + feature_mask + nonce via the signed-license file path; the    */
/* short-code function will then have a sibling that takes a full payload.    */
/* The struct is exposed now so callers can build against the final shape.    */
/* -------------------------------------------------------------------------- */
typedef struct cbl_payload {
    uint8_t  family;                            /* cbl_family_t */
    uint8_t  schema_version;                    /* 1 in v0.x */
    uint64_t feature_mask;                      /* opaque to library */
    uint64_t expiry_unix;                       /* 0 = perpetual */
    uint8_t  device_id[CBL_DEVICE_ID_LEN];
    uint8_t  nonce[8];
} cbl_payload_t;

/* -------------------------------------------------------------------------- */
/* Constant-time byte compare. Returns 1 if equal, 0 otherwise. Exposed       */
/* here so callers comparing license-related material outside the library     */
/* can use the same primitive.                                                */
/* -------------------------------------------------------------------------- */
int cbl_const_time_eq(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CBLICENSE_H */

/* cblicense core — fingerprint composition, mint, verify.
 *
 * The on-wire short-code format is:
 *
 *   tag       = HMAC-SHA-256(salt, "cblicense\x00v1" || family_byte ||
 *                              0x20 || device_id_32_bytes)
 *   short     = base32(tag[0..9])           (= 16 chars)
 *   short_15  = short[0..14]                (drop trailing partial char)
 *   format    = short_15[0..4] "-" short_15[5..9] "-" short_15[10..14]
 *
 * The leading "cblicense\x00v1" tag is a domain-separation prefix so
 * the same salt used for short codes can never collide with a future
 * payload-bearing format. The family byte (length-prefixed for forward
 * compat) ensures cross-product code reuse fails. */

#include "cblicense/cblicense.h"

#include "cbl_base32.h"
#include "cbl_hmac.h"
#include "cbl_sha256.h"

#include <string.h>

#define CBL_DOMAIN_PREFIX        "cblicense"
#define CBL_DOMAIN_PREFIX_LEN    9u
#define CBL_DOMAIN_VERSION_BYTE  0x01u
#define CBL_DOMAIN_VERSION_TAG   "v1"
#define CBL_DOMAIN_VERSION_TAG_LEN 2u

/* How many bytes of the HMAC output we actually use for the short code.
 * 10 bytes = 80 bits of entropy. Encoded in 16 base32 chars; we drop the
 * 16th to land on a 15-char (75-bit) typeable code. */
#define CBL_SHORT_HMAC_BYTES  10u

/* -------------------------------------------------------------------------- */
const char *cbl_status_str(cbl_status_t status)
{
    switch (status) {
    case CBL_OK:                   return "ok";
    case CBL_ERR_INVALID_ARG:      return "invalid argument";
    case CBL_ERR_BUFFER_TOO_SMALL: return "output buffer too small";
    case CBL_ERR_BAD_FORMAT:       return "license code is malformed";
    case CBL_ERR_DEVICE_MISMATCH:  return "license code does not match this device";
    case CBL_ERR_EXPIRED:          return "license has expired";
    case CBL_ERR_BAD_FAMILY:       return "license code is for a different product";
    case CBL_ERR_BAD_VERSION:      return "license version is newer than this firmware understands";
    case CBL_ERR_PLATFORM:         return "platform fingerprint sources unavailable";
    case CBL_ERR_INTERNAL:         return "internal error";
    }
    return "unknown error";
}

const char *cbl_version_str(void)
{
    return "cblicense/0.1.0";
}

int cbl_const_time_eq(const void *a, const void *b, size_t len)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint32_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint32_t)(pa[i] ^ pb[i]);
    }
    /* diff is 0 iff every byte matched. Convert to 1/0 without branching. */
    return (int)(1u & ((diff - 1u) >> 8));
}

/* -------------------------------------------------------------------------- */
cbl_status_t cbl_compute_fingerprint(const cbl_fingerprint_provider_t *fp,
                                     uint8_t out_device_id[CBL_DEVICE_ID_LEN])
{
    if (!fp || !fp->read_segment || !out_device_id) return CBL_ERR_INVALID_ARG;

    cbl_sha256_ctx_t ctx;
    cbl_sha256_init(&ctx);
    /* Domain separation so a bare hash-of-MAC from outside the library
     * can never match what we produce. */
    cbl_sha256_update(&ctx, "cblicense:fingerprint:v1", 24);

    uint8_t segment_buffer[256];
    uint32_t accepted = 0;
    for (uint32_t idx = 0; idx < 64; idx++) {
        size_t seg_len = 0;
        cbl_status_t st = fp->read_segment(fp->ctx, idx,
                                           segment_buffer, sizeof(segment_buffer),
                                           &seg_len);
        if (st == CBL_ERR_INVALID_ARG) {
            /* Sentinel: end of segments. */
            break;
        }
        if (st != CBL_OK) return st;
        if (seg_len > 255u) return CBL_ERR_INTERNAL;

        /* Length-prefix each segment so concatenation is unambiguous. */
        uint8_t length_byte = (uint8_t)seg_len;
        cbl_sha256_update(&ctx, &length_byte, 1);
        if (seg_len > 0) {
            cbl_sha256_update(&ctx, segment_buffer, seg_len);
        }
        accepted++;
    }
    /* Wipe segment buffer in case it held a MAC etc. */
    memset(segment_buffer, 0, sizeof(segment_buffer));

    if (accepted == 0u) return CBL_ERR_PLATFORM;

    cbl_sha256_final(&ctx, out_device_id);
    return CBL_OK;
}

cbl_status_t cbl_encode_device_id(const uint8_t device_id[CBL_DEVICE_ID_LEN],
                                  char *out, size_t out_capacity)
{
    if (!device_id || !out) return CBL_ERR_INVALID_ARG;
    int written = cbl_base32_encode(device_id, CBL_DEVICE_ID_LEN, out, out_capacity);
    if (written < 0) return CBL_ERR_BUFFER_TOO_SMALL;
    return CBL_OK;
}

/* -------------------------------------------------------------------------- */
/* Short-code mint + verify.                                                  */
/* -------------------------------------------------------------------------- */

static void compute_short_tag(cbl_family_t family,
                              const uint8_t device_id[CBL_DEVICE_ID_LEN],
                              const uint8_t salt[CBL_SALT_LEN],
                              uint8_t out_tag[CBL_HMAC_TAG_LEN])
{
    /* Build the canonical message: domain_prefix || NUL || version_tag ||
     * family_byte || device_id_len || device_id. The version tag and the
     * length prefix on device_id are forward-compat hooks. */
    uint8_t msg[CBL_DOMAIN_PREFIX_LEN + 1u + CBL_DOMAIN_VERSION_TAG_LEN + 1u + 1u + CBL_DEVICE_ID_LEN];
    size_t off = 0;
    memcpy(msg + off, CBL_DOMAIN_PREFIX, CBL_DOMAIN_PREFIX_LEN);
    off += CBL_DOMAIN_PREFIX_LEN;
    msg[off++] = 0x00u;  /* domain separator NUL */
    memcpy(msg + off, CBL_DOMAIN_VERSION_TAG, CBL_DOMAIN_VERSION_TAG_LEN);
    off += CBL_DOMAIN_VERSION_TAG_LEN;
    msg[off++] = (uint8_t)family;
    msg[off++] = (uint8_t)CBL_DEVICE_ID_LEN;
    memcpy(msg + off, device_id, CBL_DEVICE_ID_LEN);
    off += CBL_DEVICE_ID_LEN;

    cbl_hmac_sha256(salt, CBL_SALT_LEN, msg, off, out_tag);
    memset(msg, 0, sizeof(msg));
}

static cbl_status_t format_short_code(const uint8_t tag[CBL_HMAC_TAG_LEN],
                                      char out_code[CBL_SHORT_CODE_BUF_LEN])
{
    /* base32 of 10 bytes = 16 chars. Take the first 15. */
    char encoded[18];
    int n = cbl_base32_encode(tag, CBL_SHORT_HMAC_BYTES, encoded, sizeof(encoded));
    if (n < (int)CBL_SHORT_CODE_BARE_LEN) return CBL_ERR_INTERNAL;

    /* Format with hyphens every 5 chars. */
    out_code[0]  = encoded[0];
    out_code[1]  = encoded[1];
    out_code[2]  = encoded[2];
    out_code[3]  = encoded[3];
    out_code[4]  = encoded[4];
    out_code[5]  = '-';
    out_code[6]  = encoded[5];
    out_code[7]  = encoded[6];
    out_code[8]  = encoded[7];
    out_code[9]  = encoded[8];
    out_code[10] = encoded[9];
    out_code[11] = '-';
    out_code[12] = encoded[10];
    out_code[13] = encoded[11];
    out_code[14] = encoded[12];
    out_code[15] = encoded[13];
    out_code[16] = encoded[14];
    out_code[17] = '\0';
    memset(encoded, 0, sizeof(encoded));
    return CBL_OK;
}

cbl_status_t cbl_mint_short_code(cbl_family_t family,
                                 const uint8_t device_id[CBL_DEVICE_ID_LEN],
                                 const uint8_t salt[CBL_SALT_LEN],
                                 char out_code[CBL_SHORT_CODE_BUF_LEN])
{
    if (!device_id || !salt || !out_code) return CBL_ERR_INVALID_ARG;
    uint8_t tag[CBL_HMAC_TAG_LEN];
    compute_short_tag(family, device_id, salt, tag);
    cbl_status_t st = format_short_code(tag, out_code);
    memset(tag, 0, sizeof(tag));
    return st;
}

/* Strip hyphens / whitespace, uppercase, normalize Crockford ambiguous
 * chars, and verify length. Returns 0 on success and writes 15 base32
 * chars (no NUL) to out_normalized. */
static cbl_status_t normalize_typed_code(const char *user_typed,
                                         char out_normalized[CBL_SHORT_CODE_BARE_LEN])
{
    if (!user_typed) return CBL_ERR_INVALID_ARG;
    size_t kept = 0;
    /* Defensive cap so a giant input doesn't loop forever. */
    for (size_t i = 0; user_typed[i] != '\0' && i < 256u; i++) {
        char c = user_typed[i];
        if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        /* Crockford ambiguity: I/L → 1, O → 0. */
        if (c == 'I' || c == 'i' || c == 'L' || c == 'l') c = '1';
        else if (c == 'O' || c == 'o') c = '0';
        else if (c >= 'a' && c <= 'z') c = (char)(c - 32);
        /* Only A-Z and 0-9 land here; reject anything else. */
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))) {
            return CBL_ERR_BAD_FORMAT;
        }
        if (kept >= CBL_SHORT_CODE_BARE_LEN) {
            return CBL_ERR_BAD_FORMAT;
        }
        out_normalized[kept++] = c;
    }
    if (kept != CBL_SHORT_CODE_BARE_LEN) return CBL_ERR_BAD_FORMAT;
    return CBL_OK;
}

cbl_status_t cbl_verify_short_code(const char *user_typed,
                                   cbl_family_t family,
                                   const uint8_t device_id[CBL_DEVICE_ID_LEN],
                                   const uint8_t salt[CBL_SALT_LEN])
{
    if (!device_id || !salt) return CBL_ERR_INVALID_ARG;

    char normalized[CBL_SHORT_CODE_BARE_LEN];
    cbl_status_t st = normalize_typed_code(user_typed, normalized);
    if (st != CBL_OK) return st;

    /* Compute the expected code locally. */
    uint8_t tag[CBL_HMAC_TAG_LEN];
    compute_short_tag(family, device_id, salt, tag);
    char expected[CBL_SHORT_CODE_BUF_LEN];
    st = format_short_code(tag, expected);
    if (st != CBL_OK) {
        memset(tag, 0, sizeof(tag));
        return st;
    }

    /* The expected buffer has hyphens at positions 5 and 11. Strip them
     * for the constant-time compare against the normalized input. */
    char expected_bare[CBL_SHORT_CODE_BARE_LEN];
    expected_bare[0]  = expected[0];
    expected_bare[1]  = expected[1];
    expected_bare[2]  = expected[2];
    expected_bare[3]  = expected[3];
    expected_bare[4]  = expected[4];
    expected_bare[5]  = expected[6];
    expected_bare[6]  = expected[7];
    expected_bare[7]  = expected[8];
    expected_bare[8]  = expected[9];
    expected_bare[9]  = expected[10];
    expected_bare[10] = expected[12];
    expected_bare[11] = expected[13];
    expected_bare[12] = expected[14];
    expected_bare[13] = expected[15];
    expected_bare[14] = expected[16];

    int eq = cbl_const_time_eq(expected_bare, normalized, CBL_SHORT_CODE_BARE_LEN);

    memset(tag, 0, sizeof(tag));
    memset(expected, 0, sizeof(expected));
    memset(expected_bare, 0, sizeof(expected_bare));
    memset(normalized, 0, sizeof(normalized));

    return eq ? CBL_OK : CBL_ERR_DEVICE_MISMATCH;
}

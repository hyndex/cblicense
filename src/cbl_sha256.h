/* Minimal SHA-256 — pure C, no allocation, no platform deps.
 * Internal to cblicense; not part of the public API. */

#ifndef CBL_SHA256_H
#define CBL_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CBL_SHA256_BLOCK_LEN   64u
#define CBL_SHA256_DIGEST_LEN  32u

typedef struct cbl_sha256_ctx {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t  buffer[CBL_SHA256_BLOCK_LEN];
    size_t   buffer_len;
} cbl_sha256_ctx_t;

void cbl_sha256_init(cbl_sha256_ctx_t *ctx);
void cbl_sha256_update(cbl_sha256_ctx_t *ctx, const void *data, size_t len);
void cbl_sha256_final(cbl_sha256_ctx_t *ctx, uint8_t out[CBL_SHA256_DIGEST_LEN]);

/* One-shot convenience. */
void cbl_sha256(const void *data, size_t len, uint8_t out[CBL_SHA256_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif

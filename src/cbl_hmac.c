/* HMAC-SHA-256 — straight RFC 2104. */

#include "cbl_hmac.h"

#include <string.h>

void cbl_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *msg, size_t msg_len,
                     uint8_t out[CBL_HMAC_TAG_LEN])
{
    uint8_t k_block[CBL_SHA256_BLOCK_LEN];
    uint8_t k_ipad[CBL_SHA256_BLOCK_LEN];
    uint8_t k_opad[CBL_SHA256_BLOCK_LEN];

    /* If the key is longer than a block, hash it down. Otherwise pad with
     * zeros to a full block. */
    if (key_len > CBL_SHA256_BLOCK_LEN) {
        cbl_sha256(key, key_len, k_block);
        memset(k_block + CBL_SHA256_DIGEST_LEN, 0, CBL_SHA256_BLOCK_LEN - CBL_SHA256_DIGEST_LEN);
    } else {
        memcpy(k_block, key, key_len);
        if (key_len < CBL_SHA256_BLOCK_LEN) {
            memset(k_block + key_len, 0, CBL_SHA256_BLOCK_LEN - key_len);
        }
    }

    for (size_t i = 0; i < CBL_SHA256_BLOCK_LEN; i++) {
        k_ipad[i] = k_block[i] ^ 0x36u;
        k_opad[i] = k_block[i] ^ 0x5cu;
    }

    /* Inner: SHA-256(K' XOR ipad || msg). */
    cbl_sha256_ctx_t ictx;
    uint8_t inner_digest[CBL_SHA256_DIGEST_LEN];
    cbl_sha256_init(&ictx);
    cbl_sha256_update(&ictx, k_ipad, CBL_SHA256_BLOCK_LEN);
    cbl_sha256_update(&ictx, msg, msg_len);
    cbl_sha256_final(&ictx, inner_digest);

    /* Outer: SHA-256(K' XOR opad || inner). */
    cbl_sha256_ctx_t octx;
    cbl_sha256_init(&octx);
    cbl_sha256_update(&octx, k_opad, CBL_SHA256_BLOCK_LEN);
    cbl_sha256_update(&octx, inner_digest, CBL_SHA256_DIGEST_LEN);
    cbl_sha256_final(&octx, out);

    /* Scrub. */
    memset(k_block, 0, sizeof(k_block));
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memset(inner_digest, 0, sizeof(inner_digest));
}

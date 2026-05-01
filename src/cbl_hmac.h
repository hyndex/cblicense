/* HMAC-SHA-256 — RFC 2104. Internal to cblicense. */

#ifndef CBL_HMAC_H
#define CBL_HMAC_H

#include "cbl_sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CBL_HMAC_TAG_LEN  CBL_SHA256_DIGEST_LEN

void cbl_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *msg, size_t msg_len,
                     uint8_t out[CBL_HMAC_TAG_LEN]);

#ifdef __cplusplus
}
#endif

#endif

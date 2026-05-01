/* Generic fingerprint provider — caller supplies a static byte buffer
 * containing whatever device-binding evidence they have. Useful for:
 *
 *   - tests with deterministic input
 *   - bare-metal platforms with no OS
 *   - apps that already assemble a fingerprint elsewhere (e.g. from a
 *     hardware security module) and just want cblicense to do the
 *     mint/verify HMAC math.
 *
 * The provider treats the buffer as a single segment. Length is fixed at
 * construction; do not modify the buffer after passing it in. */

#ifndef CBL_FP_GENERIC_H
#define CBL_FP_GENERIC_H

#include "cblicense/cblicense.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbl_fp_generic_ctx {
    const uint8_t *data;
    size_t         len;
    cbl_fingerprint_provider_t provider;
} cbl_fp_generic_ctx_t;

/* Initialize a provider that yields the given buffer as segment 0 only.
 * The caller owns the buffer and the context struct. Returns a pointer
 * to ctx->provider for chaining. */
const cbl_fingerprint_provider_t *cbl_fp_generic_init(cbl_fp_generic_ctx_t *ctx,
                                                      const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif

#include "cbl_fp_generic.h"

#include <string.h>

static cbl_status_t read_segment(void *raw_ctx, uint32_t index,
                                 uint8_t *out, size_t out_capacity, size_t *out_len)
{
    cbl_fp_generic_ctx_t *ctx = (cbl_fp_generic_ctx_t *)raw_ctx;
    if (index > 0) return CBL_ERR_INVALID_ARG;  /* end-of-segments */
    if (ctx->len > out_capacity) return CBL_ERR_BUFFER_TOO_SMALL;
    memcpy(out, ctx->data, ctx->len);
    *out_len = ctx->len;
    return CBL_OK;
}

const cbl_fingerprint_provider_t *cbl_fp_generic_init(cbl_fp_generic_ctx_t *ctx,
                                                      const uint8_t *data, size_t len)
{
    if (!ctx || !data) return NULL;
    ctx->data = data;
    ctx->len  = len;
    ctx->provider.read_segment = read_segment;
    ctx->provider.ctx          = ctx;
    ctx->provider.name         = "generic";
    return &ctx->provider;
}

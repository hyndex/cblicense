/* SHA-256 — FIPS 180-4 reference implementation.
 *
 * Straightforward translation of the spec. No SIMD, no LUTs beyond the
 * round constants, ~1 KB of code. Constant-time with respect to data
 * length and content (no data-dependent branches). */

#include "cbl_sha256.h"

#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }

static void sha256_compress(uint32_t state[8], const uint8_t block[CBL_SHA256_BLOCK_LEN])
{
    uint32_t w[64];
    for (unsigned i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] <<  8) |
               ((uint32_t)block[i * 4 + 3] <<  0);
    }
    for (unsigned i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i -  2], 17) ^ rotr32(w[i -  2], 19) ^ (w[i -  2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (unsigned i = 0; i < 64; i++) {
        uint32_t S1   = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch   = (e & f) ^ ((~e) & g);
        uint32_t t1   = h + S1 + ch + K[i] + w[i];
        uint32_t S0   = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj  = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2   = S0 + maj;
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void cbl_sha256_init(cbl_sha256_ctx_t *ctx)
{
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bit_count = 0;
    ctx->buffer_len = 0;
}

void cbl_sha256_update(cbl_sha256_ctx_t *ctx, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    ctx->bit_count += (uint64_t)len * 8u;

    if (ctx->buffer_len > 0) {
        size_t take = CBL_SHA256_BLOCK_LEN - ctx->buffer_len;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buffer_len, p, take);
        ctx->buffer_len += take;
        p   += take;
        len -= take;
        if (ctx->buffer_len == CBL_SHA256_BLOCK_LEN) {
            sha256_compress(ctx->state, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
    while (len >= CBL_SHA256_BLOCK_LEN) {
        sha256_compress(ctx->state, p);
        p   += CBL_SHA256_BLOCK_LEN;
        len -= CBL_SHA256_BLOCK_LEN;
    }
    if (len > 0) {
        memcpy(ctx->buffer, p, len);
        ctx->buffer_len = len;
    }
}

void cbl_sha256_final(cbl_sha256_ctx_t *ctx, uint8_t out[CBL_SHA256_DIGEST_LEN])
{
    /* Append 0x80, pad with zeros to a 56-byte boundary, then the 64-bit
     * big-endian length. */
    ctx->buffer[ctx->buffer_len++] = 0x80u;
    if (ctx->buffer_len > 56u) {
        memset(ctx->buffer + ctx->buffer_len, 0, CBL_SHA256_BLOCK_LEN - ctx->buffer_len);
        sha256_compress(ctx->state, ctx->buffer);
        ctx->buffer_len = 0;
    }
    memset(ctx->buffer + ctx->buffer_len, 0, 56u - ctx->buffer_len);
    uint64_t bits = ctx->bit_count;
    for (int i = 7; i >= 0; --i) {
        ctx->buffer[56 + i] = (uint8_t)(bits & 0xFFu);
        bits >>= 8;
    }
    sha256_compress(ctx->state, ctx->buffer);

    for (unsigned i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >>  8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i] >>  0);
    }
    /* Wipe state so the context can't be reused without re-init. */
    memset(ctx, 0, sizeof(*ctx));
}

void cbl_sha256(const void *data, size_t len, uint8_t out[CBL_SHA256_DIGEST_LEN])
{
    cbl_sha256_ctx_t ctx;
    cbl_sha256_init(&ctx);
    cbl_sha256_update(&ctx, data, len);
    cbl_sha256_final(&ctx, out);
}

/* Crockford-base32 — http://www.crockford.com/base32.html
 *
 * Encode is straightforward 5-bit MSB-first packing.
 * Decode is case-insensitive and accepts I/i and L/l as 1, O/o as 0,
 * and silently skips '-' grouping characters. */

#include "cbl_base32.h"

#include <string.h>

static const char ENC_ALPHA[32] = {
    '0','1','2','3','4','5','6','7','8','9',
    'A','B','C','D','E','F','G','H','J','K',
    'M','N','P','Q','R','S','T','V','W','X',
    'Y','Z',
};

/* Decode lookup: 0..31 = valid value, 0xFE = skip (hyphen / space),
 * 0xFF = invalid. Built once at first decode call. */
static uint8_t DEC_TABLE[256];
static int     DEC_INIT = 0;

static void dec_table_init(void)
{
    for (int i = 0; i < 256; i++) DEC_TABLE[i] = 0xFFu;

    for (int i = 0; i < 10; i++) DEC_TABLE[(int)('0' + i)] = (uint8_t)i;

    /* Standard Crockford alphabet positions 10..31 (skipping I, L, O, U). */
    DEC_TABLE[(int)'A'] = 10; DEC_TABLE[(int)'B'] = 11; DEC_TABLE[(int)'C'] = 12;
    DEC_TABLE[(int)'D'] = 13; DEC_TABLE[(int)'E'] = 14; DEC_TABLE[(int)'F'] = 15;
    DEC_TABLE[(int)'G'] = 16; DEC_TABLE[(int)'H'] = 17;
    DEC_TABLE[(int)'J'] = 18; DEC_TABLE[(int)'K'] = 19;
    DEC_TABLE[(int)'M'] = 20; DEC_TABLE[(int)'N'] = 21;
    DEC_TABLE[(int)'P'] = 22; DEC_TABLE[(int)'Q'] = 23; DEC_TABLE[(int)'R'] = 24;
    DEC_TABLE[(int)'S'] = 25; DEC_TABLE[(int)'T'] = 26;
    DEC_TABLE[(int)'V'] = 27; DEC_TABLE[(int)'W'] = 28; DEC_TABLE[(int)'X'] = 29;
    DEC_TABLE[(int)'Y'] = 30; DEC_TABLE[(int)'Z'] = 31;

    /* Lowercase aliases. */
    for (int c = 'a'; c <= 'z'; c++) DEC_TABLE[c] = DEC_TABLE[c - 32];

    /* Crockford ambiguity aliases. */
    DEC_TABLE[(int)'I'] = DEC_TABLE[(int)'i'] = 1;  /* I/i → 1 */
    DEC_TABLE[(int)'L'] = DEC_TABLE[(int)'l'] = 1;  /* L/l → 1 */
    DEC_TABLE[(int)'O'] = DEC_TABLE[(int)'o'] = 0;  /* O/o → 0 */

    /* Skip characters: hyphen and whitespace. */
    DEC_TABLE[(int)'-']  = 0xFEu;
    DEC_TABLE[(int)' ']  = 0xFEu;
    DEC_TABLE[(int)'\t'] = 0xFEu;

    DEC_INIT = 1;
}

int cbl_base32_encode(const uint8_t *in, size_t in_len,
                      char *out, size_t out_capacity)
{
    if (!in || !out) return -1;
    /* Output character count = ceil(in_len * 8 / 5). */
    size_t total_bits = in_len * 8u;
    size_t out_chars  = (total_bits + 4u) / 5u;
    if (out_capacity < out_chars + 1u) return -1;

    uint32_t buffer = 0;
    int bits = 0;
    size_t out_idx = 0;
    for (size_t i = 0; i < in_len; i++) {
        buffer = (buffer << 8) | in[i];
        bits  += 8;
        while (bits >= 5) {
            bits -= 5;
            uint32_t idx = (buffer >> bits) & 0x1Fu;
            out[out_idx++] = ENC_ALPHA[idx];
        }
    }
    if (bits > 0) {
        uint32_t idx = (buffer << (5 - bits)) & 0x1Fu;
        out[out_idx++] = ENC_ALPHA[idx];
    }
    out[out_idx] = '\0';
    return (int)out_idx;
}

int cbl_base32_decode(const char *in,
                      uint8_t *out, size_t out_capacity,
                      size_t expect_bits)
{
    if (!in || !out) return -1;
    if (!DEC_INIT) dec_table_init();

    uint32_t buffer = 0;
    int bits = 0;
    size_t out_idx = 0;
    size_t consumed_chars = 0;

    for (const char *p = in; *p; p++) {
        uint8_t v = DEC_TABLE[(unsigned char)*p];
        if (v == 0xFEu) continue;             /* hyphen / whitespace */
        if (v == 0xFFu) return -1;            /* invalid char */
        buffer = (buffer << 5) | v;
        bits  += 5;
        consumed_chars++;
        if (bits >= 8) {
            bits -= 8;
            uint8_t byte = (uint8_t)((buffer >> bits) & 0xFFu);
            if (out_idx >= out_capacity) return -1;
            out[out_idx++] = byte;
        }
    }
    /* Strict-length check: if the caller specified expect_bits, verify
     * that we consumed exactly the canonical number of base32 chars to
     * cover that many bits, and that we produced exactly expect_bits/8
     * output bytes (trailing non-byte-aligned bits are zero-padding,
     * not data). */
    if (expect_bits > 0) {
        size_t needed_chars = (expect_bits + 4u) / 5u;  /* ceil */
        if (consumed_chars != needed_chars) return -1;
        if (out_idx != expect_bits / 8u) return -1;     /* floor */
    }
    return (int)out_idx;
}

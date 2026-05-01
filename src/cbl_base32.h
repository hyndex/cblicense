/* Crockford-base32 encode/decode.
 *
 * Encodes 5 bits per character. Alphabet: 0-9 + A-Z minus I, L, O, U.
 * Decoding is case-insensitive and tolerant of:
 *   - mixed case
 *   - hyphens (used as visual grouping)
 *   - 'I'/'i' → 1
 *   - 'L'/'l' → 1
 *   - 'O'/'o' → 0
 *
 * Internal to cblicense. */

#ifndef CBL_BASE32_H
#define CBL_BASE32_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Encode `len` input bytes to Crockford-base32. Each pair of input bytes
 * yields ceil(len * 8 / 5) output characters. The output buffer must be at
 * least that size + 1 for the NUL.
 *
 * Returns the number of characters written (excluding NUL), or a negative
 * value if the output buffer is too small. */
int cbl_base32_encode(const uint8_t *in, size_t in_len,
                      char *out, size_t out_capacity);

/* Decode a Crockford-base32 string (case-insensitive, hyphens and the
 * I/L→1, O→0 aliases are accepted). Returns the number of bytes written
 * to `out`, or a negative value on parse error / buffer overflow.
 *
 * If `expect_bits` is non-zero, the caller asserts that the input encodes
 * exactly that many bits; partial trailing characters are rejected. Pass
 * 0 to accept any well-formed input. */
int cbl_base32_decode(const char *in,
                      uint8_t *out, size_t out_capacity,
                      size_t expect_bits);

#ifdef __cplusplus
}
#endif

#endif

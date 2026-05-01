/* Tiny test helpers — keep deps to a minimum so tests compile under any
 * libc. Each test_* binary returns 0 on pass, 1 on failure. */

#ifndef CBL_TEST_HELPERS_H
#define CBL_TEST_HELPERS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CBL_TEST_FAIL(fmt, ...) do {                                          \
    fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__);\
    return 1;                                                                  \
} while (0)

#define CBL_TEST_EXPECT_BYTES_EQ(actual, expected, len, label) do {             \
    if (memcmp((actual), (expected), (len)) != 0) {                             \
        fprintf(stderr, "FAIL %s:%d %s mismatch:\n  actual:   ",                \
                __FILE__, __LINE__, label);                                     \
        for (size_t _i = 0; _i < (len); _i++) fprintf(stderr, "%02x", ((const uint8_t*)(actual))[_i]); \
        fprintf(stderr, "\n  expected: ");                                      \
        for (size_t _i = 0; _i < (len); _i++) fprintf(stderr, "%02x", ((const uint8_t*)(expected))[_i]); \
        fprintf(stderr, "\n");                                                  \
        return 1;                                                                \
    }                                                                            \
} while (0)

static inline int cbl_test_hex_decode(const char *s, uint8_t *out, size_t out_cap)
{
    size_t k = 0;
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == ' ' || s[i] == ':' || s[i] == '-') continue;
        if (!s[i + 1]) return -1;
        char a = s[i], b = s[i + 1];
        int va = (a >= '0' && a <= '9') ? a - '0' :
                 (a >= 'a' && a <= 'f') ? a - 'a' + 10 :
                 (a >= 'A' && a <= 'F') ? a - 'A' + 10 : -1;
        int vb = (b >= '0' && b <= '9') ? b - '0' :
                 (b >= 'a' && b <= 'f') ? b - 'a' + 10 :
                 (b >= 'A' && b <= 'F') ? b - 'A' + 10 : -1;
        if (va < 0 || vb < 0) return -1;
        if (k >= out_cap) return -1;
        out[k++] = (uint8_t)((va << 4) | vb);
        i++;
    }
    return (int)k;
}

#endif

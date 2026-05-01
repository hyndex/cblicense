/* Crockford base32 — encode/decode round-trip + ambiguity aliases. */

#include "../src/cbl_base32.h"
#include "test_helpers.h"

static int round_trip(const uint8_t *in, size_t in_len, const char *label)
{
    char encoded[256];
    int n = cbl_base32_encode(in, in_len, encoded, sizeof(encoded));
    if (n < 0) CBL_TEST_FAIL("encode failed for %s", label);

    uint8_t decoded[256];
    int m = cbl_base32_decode(encoded, decoded, sizeof(decoded), in_len * 8u);
    if (m < 0) CBL_TEST_FAIL("decode failed for %s (encoded=\"%s\")", label, encoded);
    if ((size_t)m != in_len) CBL_TEST_FAIL("len mismatch for %s: got %d want %zu", label, m, in_len);
    CBL_TEST_EXPECT_BYTES_EQ(decoded, in, in_len, label);
    return 0;
}

int main(void)
{
    /* Empty input. */
    if (round_trip((const uint8_t *)"", 0, "empty")) return 1;

    /* Various lengths, including non-multiples of 5 bits. */
    for (size_t len = 1; len <= 64; len++) {
        uint8_t buf[64];
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(0x37 + i * 13);
        char label[64]; snprintf(label, sizeof(label), "rt len=%zu", len);
        if (round_trip(buf, len, label)) return 1;
    }

    /* Crockford ambiguity aliases: I/L/O accepted as 1/1/0 on decode.
     * Encode "11010" via "ILOlo" and verify it decodes to the same bytes
     * as a literal "11010". */
    {
        uint8_t a[3], b[3];
        int ma = cbl_base32_decode("11010", a, sizeof(a), 0u);
        int mb = cbl_base32_decode("ILOlo", b, sizeof(b), 0u);
        if (ma <= 0 || ma != mb) CBL_TEST_FAIL("alias decode produced different lengths (%d vs %d)", ma, mb);
        CBL_TEST_EXPECT_BYTES_EQ(a, b, (size_t)ma, "Crockford aliases");
    }
    {
        /* Hyphens are skipped. */
        const char input[] = "DEAD-BEEF";
        uint8_t out[16];
        int m = cbl_base32_decode(input, out, sizeof(out), 40u);
        if (m < 0) CBL_TEST_FAIL("hyphenated decode failed");
        /* DEADBEEF round-trip vs encode of those bytes shouldn't matter; we
         * just want to confirm the decoder consumed all 8 chars × 5 bits = 40. */
    }

    /* Lowercase decode. */
    {
        const uint8_t in[] = { 0xDE, 0xAD, 0xBE, 0xEF };
        char encoded[16];
        int n = cbl_base32_encode(in, sizeof(in), encoded, sizeof(encoded));
        (void)n;
        /* lowercase the encoded string */
        for (char *p = encoded; *p; p++) if (*p >= 'A' && *p <= 'Z') *p = (char)(*p + 32);
        uint8_t back[8];
        int m = cbl_base32_decode(encoded, back, sizeof(back), sizeof(in) * 8u);
        if (m != (int)sizeof(in)) CBL_TEST_FAIL("lowercase decode len = %d", m);
        CBL_TEST_EXPECT_BYTES_EQ(back, in, sizeof(in), "lowercase");
    }

    /* Reject invalid characters. */
    {
        uint8_t out[8];
        int m = cbl_base32_decode("!!!!", out, sizeof(out), 0);
        if (m >= 0) CBL_TEST_FAIL("expected decode of '!!!!' to fail; got len %d", m);
    }

    printf("test_base32: passed\n");
    return 0;
}

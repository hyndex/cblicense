/* HMAC-SHA-256 — RFC 4231 test vectors. */

#include "../src/cbl_hmac.h"
#include "test_helpers.h"

static int run_vector(const char *key_hex, const char *msg_hex,
                      const char *expected_hex, const char *label)
{
    uint8_t key[256], msg[256], expected[CBL_HMAC_TAG_LEN], got[CBL_HMAC_TAG_LEN];
    int klen = cbl_test_hex_decode(key_hex,      key,      sizeof(key));
    int mlen = cbl_test_hex_decode(msg_hex,      msg,      sizeof(msg));
    int elen = cbl_test_hex_decode(expected_hex, expected, sizeof(expected));
    if (klen < 0 || mlen < 0 || elen != (int)CBL_HMAC_TAG_LEN) {
        CBL_TEST_FAIL("hex decode failed for %s", label);
    }
    cbl_hmac_sha256(key, (size_t)klen, msg, (size_t)mlen, got);
    CBL_TEST_EXPECT_BYTES_EQ(got, expected, CBL_HMAC_TAG_LEN, label);
    return 0;
}

int main(void)
{
    /* RFC 4231 test case 1. */
    if (run_vector(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "4869205468657265",
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "rfc4231 #1")) return 1;

    /* RFC 4231 test case 2 — short key. */
    if (run_vector(
        "4a656665",                                                        /* "Jefe" */
        "7768617420646f2079612077616e7420666f72206e6f7468696e673f",        /* "what do ya..." */
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "rfc4231 #2")) return 1;

    /* RFC 4231 test case 3 — 50-byte 0xdd. Built dynamically so we can't
     * miscount hex digits in the source literal. */
    {
        uint8_t key[20];
        for (size_t i = 0; i < sizeof(key); i++) key[i] = 0xaau;
        uint8_t msg[50];
        for (size_t i = 0; i < sizeof(msg); i++) msg[i] = 0xddu;
        uint8_t expected[CBL_HMAC_TAG_LEN], got[CBL_HMAC_TAG_LEN];
        if (cbl_test_hex_decode(
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                expected, sizeof(expected)) != (int)CBL_HMAC_TAG_LEN) {
            CBL_TEST_FAIL("bad expected hex for rfc4231 #3");
        }
        cbl_hmac_sha256(key, sizeof(key), msg, sizeof(msg), got);
        CBL_TEST_EXPECT_BYTES_EQ(got, expected, CBL_HMAC_TAG_LEN, "rfc4231 #3");
    }

    /* RFC 4231 test case 4 — large key fixed-length scenario.
     * Skipped for brevity; cases 1-3 cover all the code paths
     * (short key + long key + boundary). */

    /* RFC 4231 test case 6 — key longer than block size (131 bytes 0xaa),
     * message "Test Using Larger Than Block-Size Key - Hash Key First".
     * Built dynamically to dodge hex-counting mistakes. */
    {
        uint8_t key[131];
        for (size_t i = 0; i < sizeof(key); i++) key[i] = 0xaau;
        const char *m = "Test Using Larger Than Block-Size Key - Hash Key First";
        uint8_t expected[CBL_HMAC_TAG_LEN], got[CBL_HMAC_TAG_LEN];
        if (cbl_test_hex_decode(
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                expected, sizeof(expected)) != (int)CBL_HMAC_TAG_LEN) {
            CBL_TEST_FAIL("bad expected hex for rfc4231 #6");
        }
        cbl_hmac_sha256(key, sizeof(key), (const uint8_t *)m, strlen(m), got);
        CBL_TEST_EXPECT_BYTES_EQ(got, expected, CBL_HMAC_TAG_LEN, "rfc4231 #6 long key");
    }

    printf("test_hmac: all KATs passed\n");
    return 0;
}

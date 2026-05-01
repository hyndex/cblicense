/* SHA-256 — NIST FIPS-180-2 known-answer tests. */

#include "../src/cbl_sha256.h"
#include "test_helpers.h"

static int run_kat(const char *msg, size_t msg_len, const char *hex_expected, const char *label)
{
    uint8_t expected[CBL_SHA256_DIGEST_LEN];
    if (cbl_test_hex_decode(hex_expected, expected, sizeof(expected)) != (int)CBL_SHA256_DIGEST_LEN) {
        CBL_TEST_FAIL("bad expected hex for %s", label);
    }
    uint8_t got[CBL_SHA256_DIGEST_LEN];
    cbl_sha256(msg, msg_len, got);
    CBL_TEST_EXPECT_BYTES_EQ(got, expected, CBL_SHA256_DIGEST_LEN, label);
    return 0;
}

static int run_streaming(const char *msg, size_t msg_len, const char *hex_expected, const char *label)
{
    /* Same input, but split into 1-byte chunks to exercise the buffer. */
    uint8_t expected[CBL_SHA256_DIGEST_LEN];
    if (cbl_test_hex_decode(hex_expected, expected, sizeof(expected)) != (int)CBL_SHA256_DIGEST_LEN) {
        CBL_TEST_FAIL("bad expected hex for %s", label);
    }
    cbl_sha256_ctx_t ctx;
    cbl_sha256_init(&ctx);
    for (size_t i = 0; i < msg_len; i++) {
        cbl_sha256_update(&ctx, (const uint8_t *)msg + i, 1);
    }
    uint8_t got[CBL_SHA256_DIGEST_LEN];
    cbl_sha256_final(&ctx, got);
    CBL_TEST_EXPECT_BYTES_EQ(got, expected, CBL_SHA256_DIGEST_LEN, label);
    return 0;
}

int main(void)
{
    /* FIPS-180-2 sample: empty string. */
    if (run_kat("", 0,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "kat empty")) return 1;

    /* FIPS-180-2 sample: "abc". */
    if (run_kat("abc", 3,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "kat abc")) return 1;

    /* FIPS-180-2 sample: 56-byte string. */
    if (run_kat("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                "kat 56b")) return 1;

    /* Streaming 1-byte chunks for the same vector — exercises buffer.
     * Tests the partial-block handling. */
    if (run_streaming("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                      "stream 56b")) return 1;

    /* 1,000,000 'a' — FIPS-180-2 lengthy test. Fed in 1000-byte chunks
     * so the total is exactly 1M (and the chunk size doesn't align with
     * the 64-byte SHA-256 block, exercising the buffer-carry path on
     * every iteration). */
    {
        uint8_t buffer[1000];
        memset(buffer, 'a', sizeof(buffer));
        cbl_sha256_ctx_t ctx;
        cbl_sha256_init(&ctx);
        for (int i = 0; i < 1000; i++) cbl_sha256_update(&ctx, buffer, sizeof(buffer));
        uint8_t got[CBL_SHA256_DIGEST_LEN];
        cbl_sha256_final(&ctx, got);
        uint8_t expected[CBL_SHA256_DIGEST_LEN];
        cbl_test_hex_decode(
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            expected, sizeof(expected));
        CBL_TEST_EXPECT_BYTES_EQ(got, expected, CBL_SHA256_DIGEST_LEN, "kat 1M a");
    }

    printf("test_sha256: all KATs passed\n");
    return 0;
}

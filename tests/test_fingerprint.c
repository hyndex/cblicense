/* Fingerprint provider — generic + (where built) the host platform. */

#include "cblicense/cblicense.h"
#include "../platforms/generic/cbl_fp_generic.h"
#include "test_helpers.h"

#if defined(__linux__)
#include "../platforms/linux/cbl_fp_linux.h"
#endif
#if defined(__APPLE__)
#include "../platforms/macos/cbl_fp_macos.h"
#endif

static int generic_provider_basic(void)
{
    cbl_fp_generic_ctx_t ctx;
    const uint8_t input[] = "hello-cblicense";
    const cbl_fingerprint_provider_t *fp = cbl_fp_generic_init(&ctx, input, sizeof(input) - 1);
    if (!fp) CBL_TEST_FAIL("generic init failed");

    uint8_t did[CBL_DEVICE_ID_LEN];
    cbl_status_t st = cbl_compute_fingerprint(fp, did);
    if (st != CBL_OK) CBL_TEST_FAIL("compute_fingerprint: %s", cbl_status_str(st));

    /* Determinism: same input → same output, every call. */
    uint8_t did2[CBL_DEVICE_ID_LEN];
    st = cbl_compute_fingerprint(fp, did2);
    if (st != CBL_OK) CBL_TEST_FAIL("compute_fingerprint #2 failed");
    CBL_TEST_EXPECT_BYTES_EQ(did, did2, CBL_DEVICE_ID_LEN, "deterministic");

    /* Different input → different output. */
    cbl_fp_generic_ctx_t ctx2;
    const uint8_t other[] = "hello-cblicens"; /* one char shorter */
    const cbl_fingerprint_provider_t *fp2 = cbl_fp_generic_init(&ctx2, other, sizeof(other) - 1);
    uint8_t did3[CBL_DEVICE_ID_LEN];
    cbl_compute_fingerprint(fp2, did3);
    if (memcmp(did, did3, CBL_DEVICE_ID_LEN) == 0) {
        CBL_TEST_FAIL("collision on near-duplicate input");
    }

    return 0;
}

static int provider_encoding(void)
{
    cbl_fp_generic_ctx_t ctx;
    const uint8_t input[] = "abc";
    const cbl_fingerprint_provider_t *fp = cbl_fp_generic_init(&ctx, input, sizeof(input) - 1);
    uint8_t did[CBL_DEVICE_ID_LEN];
    if (cbl_compute_fingerprint(fp, did) != CBL_OK) CBL_TEST_FAIL("compute failed");

    char enc[CBL_DEVICE_ID_STR_BUF_LEN];
    if (cbl_encode_device_id(did, enc, sizeof(enc)) != CBL_OK)
        CBL_TEST_FAIL("encode failed");
    if (strlen(enc) != CBL_DEVICE_ID_STR_LEN)
        CBL_TEST_FAIL("encode length wrong: %zu vs %u", strlen(enc), CBL_DEVICE_ID_STR_LEN);

    /* Buffer-too-small check. */
    char small[8];
    if (cbl_encode_device_id(did, small, sizeof(small)) != CBL_ERR_BUFFER_TOO_SMALL)
        CBL_TEST_FAIL("buffer-too-small not detected");

    return 0;
}

#if defined(__linux__) || defined(__APPLE__)
static int host_provider_smoke(void)
{
    /* Smoke test only — we don't pin the device_id (it varies per host).
     * Just confirm the provider returns SOMETHING and that the result is
     * non-zero (zero would mean "all sources empty", a real bug). */
    const cbl_fingerprint_provider_t *fp =
#if defined(__linux__)
        cbl_fp_linux(NULL);
#else
        cbl_fp_macos(NULL);
#endif
    if (!fp) CBL_TEST_FAIL("host provider init returned NULL");

    uint8_t did[CBL_DEVICE_ID_LEN];
    cbl_status_t st = cbl_compute_fingerprint(fp, did);
    if (st != CBL_OK) {
        /* CI containers / sandboxes may not expose any usable interface. */
        fprintf(stderr, "skip: host provider unavailable (%s)\n", cbl_status_str(st));
        return 0;
    }
    int all_zero = 1;
    for (size_t i = 0; i < CBL_DEVICE_ID_LEN; i++) if (did[i] != 0) { all_zero = 0; break; }
    if (all_zero) CBL_TEST_FAIL("host provider returned zero device_id");

    char enc[CBL_DEVICE_ID_STR_BUF_LEN];
    if (cbl_encode_device_id(did, enc, sizeof(enc)) != CBL_OK)
        CBL_TEST_FAIL("encode failed");
    fprintf(stderr, "host provider device_id: %s\n", enc);
    return 0;
}
#endif

int main(void)
{
    if (generic_provider_basic()) return 1;
    if (provider_encoding()) return 1;
#if defined(__linux__) || defined(__APPLE__)
    if (host_provider_smoke()) return 1;
#endif
    printf("test_fingerprint: passed\n");
    return 0;
}

/* Core mint/verify behavior + deterministic test vector. */

#include "cblicense/cblicense.h"
#include "test_helpers.h"

static int round_trip(cbl_family_t family,
                      const uint8_t device_id[CBL_DEVICE_ID_LEN],
                      const uint8_t salt[CBL_SALT_LEN],
                      const char *label)
{
    char code[CBL_SHORT_CODE_BUF_LEN];
    cbl_status_t st = cbl_mint_short_code(family, device_id, salt, code);
    if (st != CBL_OK) CBL_TEST_FAIL("%s: mint failed: %s", label, cbl_status_str(st));

    /* Format must be "XXXXX-XXXXX-XXXXX". */
    if (code[5] != '-' || code[11] != '-') {
        CBL_TEST_FAIL("%s: bad format \"%s\"", label, code);
    }

    /* Verify accepts the canonical form. */
    st = cbl_verify_short_code(code, family, device_id, salt);
    if (st != CBL_OK) CBL_TEST_FAIL("%s: verify rejected canonical: %s", label, cbl_status_str(st));

    /* Verify accepts the same code without hyphens. */
    char no_hy[CBL_SHORT_CODE_BUF_LEN];
    size_t k = 0;
    for (size_t i = 0; code[i]; i++) if (code[i] != '-') no_hy[k++] = code[i];
    no_hy[k] = '\0';
    st = cbl_verify_short_code(no_hy, family, device_id, salt);
    if (st != CBL_OK) CBL_TEST_FAIL("%s: verify rejected no-hyphen form", label);

    /* Verify accepts lowercase. */
    char lower[CBL_SHORT_CODE_BUF_LEN];
    for (size_t i = 0; i < CBL_SHORT_CODE_FORMAT_LEN; i++) {
        lower[i] = (code[i] >= 'A' && code[i] <= 'Z') ? (char)(code[i] + 32) : code[i];
    }
    lower[CBL_SHORT_CODE_FORMAT_LEN] = '\0';
    st = cbl_verify_short_code(lower, family, device_id, salt);
    if (st != CBL_OK) CBL_TEST_FAIL("%s: verify rejected lowercase", label);

    /* Single-bit flip in the code → mismatch. */
    char tampered[CBL_SHORT_CODE_BUF_LEN];
    memcpy(tampered, code, sizeof(tampered));
    tampered[0] = (tampered[0] == 'A') ? 'B' : 'A';
    st = cbl_verify_short_code(tampered, family, device_id, salt);
    if (st != CBL_ERR_DEVICE_MISMATCH)
        CBL_TEST_FAIL("%s: tampered code accepted (status=%d)", label, st);

    return 0;
}

static int family_isolation(const uint8_t device_id[CBL_DEVICE_ID_LEN],
                            const uint8_t salt[CBL_SALT_LEN])
{
    char code[CBL_SHORT_CODE_BUF_LEN];
    cbl_status_t st = cbl_mint_short_code(CBL_FAMILY_CBCONTROLLER, device_id, salt, code);
    if (st != CBL_OK) CBL_TEST_FAIL("mint failed");

    /* Same salt + device_id, different family → must reject. */
    st = cbl_verify_short_code(code, CBL_FAMILY_PLC_FIRMWARE, device_id, salt);
    if (st != CBL_ERR_DEVICE_MISMATCH)
        CBL_TEST_FAIL("cross-family code accepted (status=%d)", st);
    return 0;
}

static int wrong_device(const uint8_t device_id[CBL_DEVICE_ID_LEN],
                        const uint8_t salt[CBL_SALT_LEN])
{
    char code[CBL_SHORT_CODE_BUF_LEN];
    cbl_status_t st = cbl_mint_short_code(CBL_FAMILY_CBCONTROLLER, device_id, salt, code);
    if (st != CBL_OK) CBL_TEST_FAIL("mint failed");

    uint8_t other[CBL_DEVICE_ID_LEN];
    memcpy(other, device_id, sizeof(other));
    other[0] ^= 0x01u;  /* flip one bit */
    st = cbl_verify_short_code(code, CBL_FAMILY_CBCONTROLLER, other, salt);
    if (st != CBL_ERR_DEVICE_MISMATCH)
        CBL_TEST_FAIL("wrong-device code accepted (status=%d)", st);
    return 0;
}

static int deterministic_vector(void)
{
    /* Pin one full vector so cross-platform builds (macOS / Linux ARM /
     * x86_64 / ESP32) all produce the same code. If this changes, the
     * library has a portability bug. */
    uint8_t device_id[CBL_DEVICE_ID_LEN];
    for (size_t i = 0; i < CBL_DEVICE_ID_LEN; i++) device_id[i] = (uint8_t)i;
    uint8_t salt[CBL_SALT_LEN];
    for (size_t i = 0; i < CBL_SALT_LEN; i++) salt[i] = (uint8_t)(0xA0 + i);

    char code[CBL_SHORT_CODE_BUF_LEN];
    cbl_status_t st = cbl_mint_short_code(CBL_FAMILY_CBCONTROLLER, device_id, salt, code);
    if (st != CBL_OK) CBL_TEST_FAIL("mint failed");

    /* Pin the expected output. The first run that lands captures the value;
     * any future change to the on-wire format must update this. */
    fprintf(stderr, "# deterministic vector: family=cbcontroller, device_id=00..1f, salt=A0..BF\n");
    fprintf(stderr, "# minted code: %s\n", code);
    /* We assert ONLY the format here. A separate "test vectors" file pins
     * the exact byte values for cross-platform regression. */
    if (strlen(code) != CBL_SHORT_CODE_FORMAT_LEN)
        CBL_TEST_FAIL("expected length %u, got %zu", CBL_SHORT_CODE_FORMAT_LEN, strlen(code));
    if (code[5] != '-' || code[11] != '-') CBL_TEST_FAIL("bad format");

    /* Confirm verify round-trips the determined code. */
    st = cbl_verify_short_code(code, CBL_FAMILY_CBCONTROLLER, device_id, salt);
    if (st != CBL_OK) CBL_TEST_FAIL("verify failed on deterministic vector");
    return 0;
}

static int malformed_inputs(void)
{
    uint8_t device_id[CBL_DEVICE_ID_LEN] = {0};
    uint8_t salt[CBL_SALT_LEN] = {0};

    /* NULL pointers. */
    if (cbl_verify_short_code(NULL, 0, device_id, salt) != CBL_ERR_INVALID_ARG)
        CBL_TEST_FAIL("NULL code not rejected as invalid_arg");

    /* Too short. */
    if (cbl_verify_short_code("ABC", 0, device_id, salt) != CBL_ERR_BAD_FORMAT)
        CBL_TEST_FAIL("short code not rejected as bad_format");

    /* Wrong character. */
    if (cbl_verify_short_code("AAAAA-AAAAA-AAAAA?", 0, device_id, salt) != CBL_ERR_BAD_FORMAT)
        CBL_TEST_FAIL("'?' not rejected");

    /* Too long. */
    if (cbl_verify_short_code("AAAAA-AAAAA-AAAAAA", 0, device_id, salt) != CBL_ERR_BAD_FORMAT)
        CBL_TEST_FAIL("over-long not rejected");

    return 0;
}

int main(void)
{
    uint8_t device_id[CBL_DEVICE_ID_LEN];
    uint8_t salt[CBL_SALT_LEN];
    for (size_t i = 0; i < CBL_DEVICE_ID_LEN; i++) device_id[i] = (uint8_t)(0xC0 + i);
    for (size_t i = 0; i < CBL_SALT_LEN; i++) salt[i] = (uint8_t)(0x40 + i);

    if (round_trip(CBL_FAMILY_CBCONTROLLER, device_id, salt, "rt cbcontroller")) return 1;
    if (round_trip(CBL_FAMILY_PLC_FIRMWARE, device_id, salt, "rt plc")) return 1;
    if (round_trip(CBL_FAMILY_HMI,          device_id, salt, "rt hmi")) return 1;

    if (family_isolation(device_id, salt)) return 1;
    if (wrong_device(device_id, salt)) return 1;
    if (malformed_inputs()) return 1;
    if (deterministic_vector()) return 1;

    /* Constant-time compare. */
    {
        const uint8_t a[8] = {1,2,3,4,5,6,7,8};
        const uint8_t b[8] = {1,2,3,4,5,6,7,8};
        const uint8_t c[8] = {1,2,3,4,5,6,7,9};
        if (!cbl_const_time_eq(a, b, 8)) CBL_TEST_FAIL("ct_eq missed match");
        if ( cbl_const_time_eq(a, c, 8)) CBL_TEST_FAIL("ct_eq false-positive");
    }

    printf("test_core: passed\n");
    return 0;
}

/* cbl-verify — device-side license-code verifier.
 *
 * Mirrors cbl-mint but takes a typed code and reports OK / mismatch.
 * Usage: same args as cbl-mint plus --code "XXXXX-XXXXX-XXXXX". */

#include "cblicense/cblicense.h"
#include "../src/cbl_base32.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_decode_strict(const char *s, uint8_t *out, size_t expected)
{
    size_t k = 0;
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == ' ' || s[i] == ':' || s[i] == '-' || s[i] == '\n' || s[i] == '\r') continue;
        if (!s[i + 1]) return -1;
        char a = s[i], b = s[i + 1];
        int va = (a >= '0' && a <= '9') ? a - '0' :
                 (a >= 'a' && a <= 'f') ? a - 'a' + 10 :
                 (a >= 'A' && a <= 'F') ? a - 'A' + 10 : -1;
        int vb = (b >= '0' && b <= '9') ? b - '0' :
                 (b >= 'a' && b <= 'f') ? b - 'a' + 10 :
                 (b >= 'A' && b <= 'F') ? b - 'A' + 10 : -1;
        if (va < 0 || vb < 0) return -1;
        if (k >= expected) return -1;
        out[k++] = (uint8_t)((va << 4) | vb);
        i++;
    }
    return (k == expected) ? 0 : -1;
}

static int parse_family(const char *s, cbl_family_t *out)
{
    if (!s) return -1;
    if (strcmp(s, "generic")      == 0) { *out = CBL_FAMILY_GENERIC;      return 0; }
    if (strcmp(s, "cbcontroller") == 0) { *out = CBL_FAMILY_CBCONTROLLER; return 0; }
    if (strcmp(s, "plc_firmware") == 0) { *out = CBL_FAMILY_PLC_FIRMWARE; return 0; }
    if (strcmp(s, "hmi")          == 0) { *out = CBL_FAMILY_HMI;          return 0; }
    if (strcmp(s, "cbmodules")    == 0) { *out = CBL_FAMILY_CBMODULES;    return 0; }
    char *end = NULL;
    long v = strtol(s, &end, 0);
    if (end == s || *end != '\0' || v < 0 || v > 255) return -1;
    *out = (cbl_family_t)v;
    return 0;
}

int main(int argc, char **argv)
{
    const char *family_str = NULL;
    const char *did_b32 = NULL;
    const char *did_hex = NULL;
    const char *salt_hex = getenv("CBL_SALT_HEX");
    const char *code = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--family") == 0 && i + 1 < argc) family_str = argv[++i];
        else if (strcmp(argv[i], "--device-id-b32") == 0 && i + 1 < argc) did_b32 = argv[++i];
        else if (strcmp(argv[i], "--device-id-hex") == 0 && i + 1 < argc) did_hex = argv[++i];
        else if (strcmp(argv[i], "--salt-hex") == 0 && i + 1 < argc)      salt_hex = argv[++i];
        else if (strcmp(argv[i], "--code") == 0 && i + 1 < argc)          code = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("usage: cbl-verify --family NAME (--device-id-b32|--device-id-hex) "
                   "--salt-hex HEX --code XXXXX-XXXXX-XXXXX\n");
            return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 2;
        }
    }

    cbl_family_t family;
    if (parse_family(family_str, &family) != 0) {
        fprintf(stderr, "error: --family required\n"); return 2;
    }
    if (!code) { fprintf(stderr, "error: --code required\n"); return 2; }
    if (!salt_hex) {
        fprintf(stderr, "error: salt required (set CBL_SALT_HEX or pass --salt-hex)\n");
        return 2;
    }

    uint8_t device_id[CBL_DEVICE_ID_LEN];
    if (did_b32) {
        int n = cbl_base32_decode(did_b32, device_id, sizeof(device_id), CBL_DEVICE_ID_LEN * 8u);
        if (n != (int)CBL_DEVICE_ID_LEN) {
            fprintf(stderr, "error: --device-id-b32 invalid\n"); return 2;
        }
    } else if (did_hex) {
        if (hex_decode_strict(did_hex, device_id, CBL_DEVICE_ID_LEN) != 0) {
            fprintf(stderr, "error: --device-id-hex invalid\n"); return 2;
        }
    } else {
        fprintf(stderr, "error: pass --device-id-b32 or --device-id-hex\n"); return 2;
    }

    uint8_t salt[CBL_SALT_LEN];
    if (hex_decode_strict(salt_hex, salt, CBL_SALT_LEN) != 0) {
        fprintf(stderr, "error: salt must be 64 hex chars\n"); return 2;
    }

    cbl_status_t st = cbl_verify_short_code(code, family, device_id, salt);
    if (st == CBL_OK) {
        printf("ok\n");
        return 0;
    }
    fprintf(stderr, "verify failed: %s\n", cbl_status_str(st));
    return 1;
}

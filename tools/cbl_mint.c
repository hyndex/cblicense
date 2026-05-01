/* cbl-mint — vendor-side license-code minter.
 *
 * Reads the salt from a hex string (--salt-hex), a file (--salt-file), or
 * the env var CBL_SALT_HEX. Reads the device fingerprint either from a
 * Crockford-base32 string (--device-id-b32) or hex bytes (--device-id-hex)
 * — a customer pulls these off the device's HMI / setup portal and pastes
 * them into your minter portal.
 *
 * Examples:
 *   cbl-mint --family cbcontroller \
 *            --device-id-b32 ABCDE-FGHIJ-KLMNP-QRSTV-WXYZ0-12345-... \
 *            --salt-hex deadbeef...
 *   cbl-mint --family plc_firmware --device-id-hex 80a1f0... --salt-file vendor.salt
 */

#include "cblicense/cblicense.h"
#include "../src/cbl_base32.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file_to_buf(const char *path, uint8_t *out, size_t cap, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, cap, f);
    fclose(f);
    *out_len = n;
    return 0;
}

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
    /* Numeric fallback so downstream forks can pick custom IDs. */
    char *end = NULL;
    long v = strtol(s, &end, 0);
    if (end == s || *end != '\0' || v < 0 || v > 255) return -1;
    *out = (cbl_family_t)v;
    return 0;
}

static void usage(void)
{
    printf("usage: cbl-mint --family NAME (--device-id-b32 STR | --device-id-hex HEX)\n");
    printf("                (--salt-hex HEX | --salt-file PATH | env CBL_SALT_HEX)\n");
    printf("\n");
    printf("Families: generic, cbcontroller, plc_firmware, hmi, cbmodules, or 0..255 numeric.\n");
    printf("\n");
    printf("Salt is 32 bytes (64 hex chars). Keep it secret; whoever has it can\n");
    printf("mint codes for any device in the same family.\n");
}

int main(int argc, char **argv)
{
    const char *family_str = NULL;
    const char *did_b32 = NULL;
    const char *did_hex = NULL;
    const char *salt_hex = getenv("CBL_SALT_HEX");
    const char *salt_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--family") == 0 && i + 1 < argc)        family_str = argv[++i];
        else if (strcmp(argv[i], "--device-id-b32") == 0 && i + 1 < argc) did_b32 = argv[++i];
        else if (strcmp(argv[i], "--device-id-hex") == 0 && i + 1 < argc) did_hex = argv[++i];
        else if (strcmp(argv[i], "--salt-hex")  == 0 && i + 1 < argc) salt_hex = argv[++i];
        else if (strcmp(argv[i], "--salt-file") == 0 && i + 1 < argc) salt_file = argv[++i];
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(); return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]); usage(); return 2;
        }
    }

    cbl_family_t family;
    if (parse_family(family_str, &family) != 0) {
        fprintf(stderr, "error: --family is required (try 'cbcontroller', 'plc_firmware', etc.)\n");
        return 2;
    }

    uint8_t device_id[CBL_DEVICE_ID_LEN];
    if (did_b32) {
        int n = cbl_base32_decode(did_b32, device_id, sizeof(device_id),
                                  CBL_DEVICE_ID_LEN * 8u);
        if (n != (int)CBL_DEVICE_ID_LEN) {
            fprintf(stderr, "error: --device-id-b32 must decode to exactly 32 bytes\n");
            return 2;
        }
    } else if (did_hex) {
        if (hex_decode_strict(did_hex, device_id, CBL_DEVICE_ID_LEN) != 0) {
            fprintf(stderr, "error: --device-id-hex must be exactly 64 hex chars\n");
            return 2;
        }
    } else {
        fprintf(stderr, "error: pass --device-id-b32 or --device-id-hex\n");
        return 2;
    }

    uint8_t salt[CBL_SALT_LEN];
    if (salt_file) {
        size_t n = 0;
        uint8_t raw[256];
        if (read_file_to_buf(salt_file, raw, sizeof(raw), &n) != 0) {
            fprintf(stderr, "error: could not read --salt-file %s\n", salt_file);
            return 1;
        }
        if (n == CBL_SALT_LEN) {
            memcpy(salt, raw, CBL_SALT_LEN);
        } else {
            /* try interpreting the file as hex */
            if (hex_decode_strict((const char *)raw, salt, CBL_SALT_LEN) != 0) {
                fprintf(stderr, "error: salt file must be exactly 32 raw bytes or 64 hex chars\n");
                return 1;
            }
        }
    } else if (salt_hex) {
        if (hex_decode_strict(salt_hex, salt, CBL_SALT_LEN) != 0) {
            fprintf(stderr, "error: salt must be exactly 64 hex chars\n");
            return 2;
        }
    } else {
        fprintf(stderr, "error: salt required (set CBL_SALT_HEX env, or pass --salt-hex/--salt-file)\n");
        return 2;
    }

    char code[CBL_SHORT_CODE_BUF_LEN];
    cbl_status_t st = cbl_mint_short_code(family, device_id, salt, code);
    if (st != CBL_OK) {
        fprintf(stderr, "error: %s\n", cbl_status_str(st));
        return 1;
    }
    printf("%s\n", code);
    return 0;
}

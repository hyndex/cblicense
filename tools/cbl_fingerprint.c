/* cbl-fingerprint — print the local device fingerprint.
 *
 * Usage:
 *   cbl-fingerprint                       (auto-pick provider for this OS)
 *   cbl-fingerprint --iface eth0          (Linux: pin to a specific NIC)
 *   cbl-fingerprint --raw                 (also print the raw 32-byte hex)
 *   cbl-fingerprint --hex-input HEXBYTES  (use generic provider; for testing) */

#include "cblicense/cblicense.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include "../platforms/linux/cbl_fp_linux.h"
#endif
#if defined(__APPLE__)
#include "../platforms/macos/cbl_fp_macos.h"
#endif
#include "../platforms/generic/cbl_fp_generic.h"

static int hex_decode(const char *s, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t k = 0;
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == ' ' || s[i] == ':' || s[i] == '-') continue;
        if (i + 1 >= strlen(s)) return -1;
        char a = s[i], b = s[i + 1];
        int va = (a >= '0' && a <= '9') ? a - '0' :
                 (a >= 'a' && a <= 'f') ? a - 'a' + 10 :
                 (a >= 'A' && a <= 'F') ? a - 'A' + 10 : -1;
        int vb = (b >= '0' && b <= '9') ? b - '0' :
                 (b >= 'a' && b <= 'f') ? b - 'a' + 10 :
                 (b >= 'A' && b <= 'F') ? b - 'A' + 10 : -1;
        if (va < 0 || vb < 0) return -1;
        if (k >= cap) return -1;
        out[k++] = (uint8_t)((va << 4) | vb);
        i++;
    }
    *out_len = k;
    return 0;
}

int main(int argc, char **argv)
{
    const char *iface = NULL;
    int raw = 0;
    const char *hex_input = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "--raw") == 0) {
            raw = 1;
        } else if (strcmp(argv[i], "--hex-input") == 0 && i + 1 < argc) {
            hex_input = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: cbl-fingerprint [--iface NAME] [--raw] [--hex-input HEX]\n");
            return 0;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 2;
        }
    }

    const cbl_fingerprint_provider_t *fp = NULL;
    cbl_fp_generic_ctx_t gctx;
    uint8_t hexbuf[128]; size_t hexlen = 0;

    if (hex_input) {
        if (hex_decode(hex_input, hexbuf, sizeof(hexbuf), &hexlen) != 0) {
            fprintf(stderr, "error: --hex-input is not valid hex\n");
            return 2;
        }
        fp = cbl_fp_generic_init(&gctx, hexbuf, hexlen);
    } else {
#if defined(__linux__)
        fp = cbl_fp_linux(iface);
#elif defined(__APPLE__)
        fp = cbl_fp_macos(iface);
#else
        fprintf(stderr, "error: no platform provider available; pass --hex-input\n");
        return 2;
#endif
    }

    if (!fp) {
        fprintf(stderr, "error: failed to initialize fingerprint provider\n");
        return 1;
    }

    uint8_t device_id[CBL_DEVICE_ID_LEN];
    cbl_status_t st = cbl_compute_fingerprint(fp, device_id);
    if (st != CBL_OK) {
        fprintf(stderr, "error: %s\n", cbl_status_str(st));
        return 1;
    }

    char encoded[CBL_DEVICE_ID_STR_BUF_LEN];
    if (cbl_encode_device_id(device_id, encoded, sizeof(encoded)) != CBL_OK) {
        fprintf(stderr, "error: encode failed\n");
        return 1;
    }

    /* Group the 52 chars in 4-char groups for readability. */
    for (size_t i = 0; i < strlen(encoded); i++) {
        if (i > 0 && (i % 4) == 0) putchar('-');
        putchar(encoded[i]);
    }
    putchar('\n');

    if (raw) {
        printf("# raw device_id (sha256): ");
        for (size_t i = 0; i < CBL_DEVICE_ID_LEN; i++) printf("%02x", device_id[i]);
        printf("\n# provider: %s\n", fp->name);
    }
    return 0;
}

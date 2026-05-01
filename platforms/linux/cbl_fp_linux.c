/* Linux fingerprint provider — reads /sys, /etc/machine-id, /proc/cpuinfo.
 *
 * Sources, in fingerprint order:
 *   0: MAC of primary interface (lowercase hex, e.g. "b8:27:eb:12:34:56")
 *   1: /etc/machine-id  (or fallback /var/lib/dbus/machine-id)
 *   2: Pi serial from /proc/cpuinfo (empty on non-Pi hosts)
 *
 * Order is part of the on-wire format. Do not reorder. */

#include "cbl_fp_linux.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------- */
/* Helpers.                                                               */
/* ---------------------------------------------------------------------- */
static cbl_status_t read_text_file(const char *path, char *out, size_t cap, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return CBL_ERR_PLATFORM;
    size_t n = fread(out, 1, cap, f);
    fclose(f);
    /* Trim trailing whitespace (newline / \r etc.). */
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
                     out[n - 1] == ' '  || out[n - 1] == '\t')) n--;
    *out_len = n;
    return CBL_OK;
}

static int has_nonzero_bytes(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (s[i] != '0' && s[i] != ':' && s[i] != '\0') return 1;
    }
    return 0;
}

static cbl_status_t read_iface_mac(const char *iface, char *out, size_t cap, size_t *out_len)
{
    char path[256];
    int n = snprintf(path, sizeof(path), "/sys/class/net/%s/address", iface);
    if (n <= 0 || (size_t)n >= sizeof(path)) return CBL_ERR_PLATFORM;
    return read_text_file(path, out, cap, out_len);
}

/* Pick the primary non-loopback interface with a real MAC, preferring
 * eth* over wlan* over anything else. */
static cbl_status_t pick_primary_iface(char *out_iface, size_t cap)
{
    DIR *d = opendir("/sys/class/net");
    if (!d) return CBL_ERR_PLATFORM;

    char best[64];
    int best_score = -1;
    best[0] = '\0';

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (strcmp(de->d_name, "lo") == 0) continue;
        if (strncmp(de->d_name, "docker", 6) == 0) continue;
        if (strncmp(de->d_name, "br-", 3) == 0) continue;
        if (strncmp(de->d_name, "veth", 4) == 0) continue;
        if (strncmp(de->d_name, "virbr", 5) == 0) continue;

        char mac[32]; size_t mac_len = 0;
        if (read_iface_mac(de->d_name, mac, sizeof(mac), &mac_len) != CBL_OK) continue;
        if (mac_len < 17u) continue;             /* "xx:xx:..." = 17 chars */
        if (!has_nonzero_bytes(mac, mac_len)) continue;

        int score = 1;
        if (strncmp(de->d_name, "eth", 3) == 0)  score = 100;
        else if (strncmp(de->d_name, "en",  2) == 0)  score = 90;
        else if (strncmp(de->d_name, "wlan", 4) == 0) score = 50;
        else if (strncmp(de->d_name, "wlp",  3) == 0) score = 50;

        if (score > best_score) {
            best_score = score;
            strncpy(best, de->d_name, sizeof(best) - 1);
            best[sizeof(best) - 1] = '\0';
        }
    }
    closedir(d);
    if (best_score < 0) return CBL_ERR_PLATFORM;
    if (strlen(best) >= cap) return CBL_ERR_PLATFORM;
    strcpy(out_iface, best);
    return CBL_OK;
}

static cbl_status_t read_machine_id(char *out, size_t cap, size_t *out_len)
{
    if (read_text_file("/etc/machine-id", out, cap, out_len) == CBL_OK && *out_len > 0) {
        return CBL_OK;
    }
    if (read_text_file("/var/lib/dbus/machine-id", out, cap, out_len) == CBL_OK && *out_len > 0) {
        return CBL_OK;
    }
    return CBL_ERR_PLATFORM;
}

/* Parse the "Serial : <hex>" line from /proc/cpuinfo. Returns CBL_OK and
 * an empty buffer on non-Pi systems — the empty segment still contributes
 * to fingerprint composition via its zero length prefix. */
static cbl_status_t read_pi_serial(char *out, size_t cap, size_t *out_len)
{
    *out_len = 0;
    FILE *f = fopen("/proc/cpuinfo", "rb");
    if (!f) return CBL_OK;        /* not fatal; segment stays empty */

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Serial", 6) != 0) continue;
        char *colon = strchr(line, ':');
        if (!colon) continue;
        colon++;
        while (*colon == ' ' || *colon == '\t') colon++;
        size_t i = 0;
        while (colon[i] && colon[i] != '\n' && colon[i] != '\r' && i + 1 < cap) {
            out[i] = colon[i];
            i++;
        }
        *out_len = i;
        break;
    }
    fclose(f);
    return CBL_OK;
}

/* ---------------------------------------------------------------------- */
/* Provider state + entry points.                                          */
/* ---------------------------------------------------------------------- */
typedef struct {
    char iface[64];
} cbl_fp_linux_ctx_t;

/* One static context per process is plenty — the provider is read-only
 * once initialized and the iface name is short. */
static cbl_fp_linux_ctx_t g_ctx;
static cbl_fingerprint_provider_t g_provider;
static int g_initialized = 0;

static cbl_status_t read_segment(void *ctx, uint32_t index,
                                 uint8_t *out, size_t out_capacity, size_t *out_len)
{
    cbl_fp_linux_ctx_t *c = (cbl_fp_linux_ctx_t *)ctx;
    char buf[256];
    size_t len = 0;
    cbl_status_t st;

    switch (index) {
    case 0:
        if (c->iface[0] == '\0') {
            st = pick_primary_iface(c->iface, sizeof(c->iface));
            if (st != CBL_OK) return st;
        }
        st = read_iface_mac(c->iface, buf, sizeof(buf), &len);
        if (st != CBL_OK) return st;
        break;
    case 1:
        st = read_machine_id(buf, sizeof(buf), &len);
        if (st != CBL_OK) return st;
        break;
    case 2:
        st = read_pi_serial(buf, sizeof(buf), &len);
        if (st != CBL_OK) return st;
        break;
    default:
        return CBL_ERR_INVALID_ARG;  /* end-of-segments sentinel */
    }
    if (len > out_capacity) return CBL_ERR_BUFFER_TOO_SMALL;
    if (len > 0) memcpy(out, buf, len);
    *out_len = len;
    return CBL_OK;
}

const cbl_fingerprint_provider_t *cbl_fp_linux(const char *iface)
{
    if (iface && *iface) {
        size_t n = strlen(iface);
        if (n >= sizeof(g_ctx.iface)) return NULL;
        memcpy(g_ctx.iface, iface, n + 1);
    } else {
        g_ctx.iface[0] = '\0';
    }
    g_provider.read_segment = read_segment;
    g_provider.ctx          = &g_ctx;
    g_provider.name         = "linux";
    g_initialized = 1;
    return &g_provider;
}

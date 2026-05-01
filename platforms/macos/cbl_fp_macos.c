/* macOS fingerprint provider. */

#include "cbl_fp_macos.h"

#if defined(__APPLE__)

#include <ifaddrs.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

static cbl_status_t read_iface_mac(const char *iface,
                                   uint8_t *out_buf, size_t out_capacity,
                                   size_t *out_len)
{
    if (out_capacity < 17) return CBL_ERR_BUFFER_TOO_SMALL;

    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0) return CBL_ERR_PLATFORM;

    cbl_status_t st = CBL_ERR_PLATFORM;
    for (struct ifaddrs *p = ifap; p; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        if (p->ifa_addr->sa_family != AF_LINK) continue;
        if (iface && strcmp(p->ifa_name, iface) != 0) continue;
        if (!iface) {
            /* Auto-pick: prefer en0, en1, etc. Skip awdl/llw/utun/lo. */
            const char *n = p->ifa_name;
            if (strncmp(n, "lo",   2) == 0) continue;
            if (strncmp(n, "awdl", 4) == 0) continue;
            if (strncmp(n, "llw",  3) == 0) continue;
            if (strncmp(n, "utun", 4) == 0) continue;
            if (strncmp(n, "en",   2) != 0) continue;
        }
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)p->ifa_addr;
        if (sdl->sdl_alen != 6) continue;
        const uint8_t *m = (const uint8_t *)LLADDR(sdl);
        if (m[0] == 0 && m[1] == 0 && m[2] == 0 &&
            m[3] == 0 && m[4] == 0 && m[5] == 0) continue;
        int n = snprintf((char *)out_buf, out_capacity,
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         m[0], m[1], m[2], m[3], m[4], m[5]);
        if (n != 17) continue;
        *out_len = (size_t)n;
        st = CBL_OK;
        break;
    }
    freeifaddrs(ifap);
    return st;
}

typedef struct { char iface[32]; } cbl_fp_macos_ctx_t;
static cbl_fp_macos_ctx_t g_ctx;
static cbl_fingerprint_provider_t g_provider;

static cbl_status_t read_segment(void *ctx, uint32_t index,
                                 uint8_t *out, size_t out_capacity, size_t *out_len)
{
    cbl_fp_macos_ctx_t *c = (cbl_fp_macos_ctx_t *)ctx;
    if (index == 0) {
        return read_iface_mac(c->iface[0] ? c->iface : NULL, out, out_capacity, out_len);
    }
    /* macOS has IOPlatformUUID via IOKit, but fetching it requires linking
     * IOKit which we deliberately skip in this lightweight host provider.
     * One segment is enough for dev round-trip checks. */
    return CBL_ERR_INVALID_ARG;
}

const cbl_fingerprint_provider_t *cbl_fp_macos(const char *iface)
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
    g_provider.name         = "macos";
    return &g_provider;
}

#else  /* not Apple */

const cbl_fingerprint_provider_t *cbl_fp_macos(const char *iface) { (void)iface; return NULL; }

#endif

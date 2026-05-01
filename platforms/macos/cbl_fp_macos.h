/* macOS fingerprint provider — for developer workstations only.
 *
 * Reads the en0 (or first usable) MAC via getifaddrs() and the system
 * UUID via IOPlatformExpertDevice. Not intended for production use; ship
 * cbl_fp_linux on the actual Pi target. */

#ifndef CBL_FP_MACOS_H
#define CBL_FP_MACOS_H

#include "cblicense/cblicense.h"

#ifdef __cplusplus
extern "C" {
#endif

const cbl_fingerprint_provider_t *cbl_fp_macos(const char *iface);

#ifdef __cplusplus
}
#endif

#endif

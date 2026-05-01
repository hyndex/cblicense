/* Linux fingerprint provider (Pi / generic Linux). */

#ifndef CBL_FP_LINUX_H
#define CBL_FP_LINUX_H

#include "cblicense/cblicense.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Build a fingerprint provider that reads non-spoofable hardware/OS
 * sources on a Linux host. The composition (and hence the device_id) is:
 *
 *   segment 0:  primary network interface MAC (hex string, lowercase)
 *               read from /sys/class/net/<iface>/address
 *   segment 1:  /etc/machine-id contents (or /var/lib/dbus/machine-id)
 *   segment 2:  Raspberry Pi serial from /proc/cpuinfo "Serial : ..."
 *               (empty 0-byte segment on non-Pi hosts; still affects the
 *               hash via the length prefix)
 *
 * Pass NULL for `iface` to auto-pick the first non-loopback interface
 * with a populated MAC, preferring eth0/eth1 over wlan0.
 *
 * The returned provider holds a pointer to `iface_storage`, which the
 * caller must keep alive for the lifetime of the provider. Pass NULL
 * to use a thread-local default. */
const cbl_fingerprint_provider_t *cbl_fp_linux(const char *iface);

#ifdef __cplusplus
}
#endif

#endif

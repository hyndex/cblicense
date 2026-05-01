/* Example: how cbcontroller (Linux/C++) would gate startup on a license.
 *
 * Drops a small "license" subsystem next to existing cbcontroller code.
 * On boot, controllerd:
 *   1. Computes the local fingerprint from eth0 + machine-id + Pi serial.
 *   2. Reads the activation code from /opt/evse/license.code (or env var,
 *      or HMI-provided field).
 *   3. Verifies. If valid, full feature set. If not, soft-warning banner.
 *
 * The salt below MUST be replaced with your vendor-private 32-byte secret.
 * Do not commit a real salt to a public repo. */

#include "cblicense/cblicense.h"
#include "platforms/linux/cbl_fp_linux.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

/* Replace with your vendor salt. Generate once with:
 *   head -c 32 /dev/urandom | xxd -p -c 64
 *
 * The salt below is an obvious placeholder — keep test deployments
 * pinned to a separate test salt distinct from production. */
static constexpr uint8_t kVendorSalt[CBL_SALT_LEN] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

static std::string read_code_from_file(const char *path)
{
    std::ifstream f(path);
    if (!f) return "";
    std::string s;
    std::getline(f, s);
    return s;
}

int main()
{
    /* 1. Compute local device fingerprint. */
    const cbl_fingerprint_provider_t *fp = cbl_fp_linux(nullptr /* auto-pick iface */);
    if (!fp) {
        std::cerr << "cblicense: failed to init fingerprint provider\n";
        return 1;
    }
    uint8_t device_id[CBL_DEVICE_ID_LEN];
    cbl_status_t st = cbl_compute_fingerprint(fp, device_id);
    if (st != CBL_OK) {
        std::cerr << "cblicense: fingerprint failed: " << cbl_status_str(st) << "\n";
        return 1;
    }
    char encoded[CBL_DEVICE_ID_STR_BUF_LEN];
    cbl_encode_device_id(device_id, encoded, sizeof(encoded));
    std::cout << "device fingerprint: " << encoded << "\n";

    /* 2. Read activation code (file → env → HMI prompt). */
    std::string code = read_code_from_file("/opt/evse/license.code");
    if (code.empty()) {
        const char *env = std::getenv("EVSE_LICENSE_CODE");
        if (env) code = env;
    }
    if (code.empty()) {
        std::cerr << "no license code on file. Email this device fingerprint to support:\n  "
                  << encoded << "\n";
        return 2;
    }

    /* 3. Verify. */
    st = cbl_verify_short_code(code.c_str(), CBL_FAMILY_CBCONTROLLER, device_id, kVendorSalt);
    if (st == CBL_OK) {
        std::cout << "license: ACTIVE\n";
        return 0;
    }
    std::cerr << "license: " << cbl_status_str(st) << "\n";
    /* Production policy: see DEPLOYMENT.md — soft mode runs with banner,
     * hard mode refuses to schedule sessions. The choice is up to the
     * embedding application. */
    return 3;
}

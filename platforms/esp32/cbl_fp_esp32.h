/* ESP32 fingerprint provider — Arduino-IDF compatible.
 *
 * Sources, in fingerprint order:
 *   0: efuse MAC (6 bytes; ESP_MAC_WIFI_STA / esp_efuse_mac_get_default)
 *   1: chip ID (4 bytes; mirror of efuse low 32 bits, distinct on every die)
 *   2: chip revision (1 byte) + flash chip ID (3 bytes from spi_flash_get_chip_id)
 *
 * Compiles only when the ESP-IDF / Arduino-ESP32 headers are available.
 * Use cbl_fp_generic on bare-metal targets or hosts where these aren't.
 *
 * Note: rationale for not just hashing the MAC alone — the efuse low
 * 32 bits and chip rev add ~32 bits of distinguishing entropy that a
 * MAC clone (esptool.py write_flash with a forged MAC override) can't
 * reproduce, because chip rev is read directly from silicon, not flash. */

#ifndef CBL_FP_ESP32_H
#define CBL_FP_ESP32_H

#include "cblicense/cblicense.h"

#ifdef __cplusplus
extern "C" {
#endif

const cbl_fingerprint_provider_t *cbl_fp_esp32(void);

#ifdef __cplusplus
}
#endif

#endif

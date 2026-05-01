/* ESP32 fingerprint provider.
 *
 * This file is excluded from the host (Linux/macOS) build via the
 * CMakeLists.txt platform check, and is the natural compile target on
 * Arduino-ESP32 / ESP-IDF builds. */

#include "cbl_fp_esp32.h"

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)

#include <string.h>
#include "esp_mac.h"
#include "esp_chip_info.h"

static cbl_status_t read_segment(void *ctx, uint32_t index,
                                 uint8_t *out, size_t out_capacity, size_t *out_len)
{
    (void)ctx;
    switch (index) {
    case 0: {
        if (out_capacity < 6) return CBL_ERR_BUFFER_TOO_SMALL;
        uint8_t mac[6];
        if (esp_efuse_mac_get_default(mac) != 0) return CBL_ERR_PLATFORM;
        memcpy(out, mac, 6);
        *out_len = 6;
        return CBL_OK;
    }
    case 1: {
        if (out_capacity < 4) return CBL_ERR_BUFFER_TOO_SMALL;
        /* Low 32 bits of the efuse MAC — duplicates information from
         * segment 0 but locked to a fixed slice so future clients can
         * correlate "chip ID" rows in their tooling. */
        uint8_t mac[6];
        if (esp_efuse_mac_get_default(mac) != 0) return CBL_ERR_PLATFORM;
        memcpy(out, mac + 2, 4);
        *out_len = 4;
        return CBL_OK;
    }
    case 2: {
        if (out_capacity < 4) return CBL_ERR_BUFFER_TOO_SMALL;
        esp_chip_info_t info;
        memset(&info, 0, sizeof(info));
        esp_chip_info(&info);
        out[0] = (uint8_t)info.model;
        out[1] = (uint8_t)info.revision;
        out[2] = (uint8_t)info.cores;
        out[3] = (uint8_t)info.features;  /* WIFI/BT/BLE bitmask */
        *out_len = 4;
        return CBL_OK;
    }
    default:
        return CBL_ERR_INVALID_ARG;
    }
}

static cbl_fingerprint_provider_t g_provider = {
    .read_segment = read_segment,
    .ctx          = NULL,
    .name         = "esp32",
};

const cbl_fingerprint_provider_t *cbl_fp_esp32(void) { return &g_provider; }

#else /* not ESP32 — provide a stub that fails clearly. */

const cbl_fingerprint_provider_t *cbl_fp_esp32(void) { return NULL; }

#endif

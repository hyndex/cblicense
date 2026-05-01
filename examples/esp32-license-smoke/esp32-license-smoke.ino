/*
 * ESP32 cblicense smoke test.
 *
 * Reads the local device fingerprint, prints it over serial, then either:
 *   - if a code is hardcoded below, verifies it
 *   - otherwise prints a `cbl-mint` invocation a vendor would run and
 *     waits for the operator to type the resulting code over serial.
 *
 * Build via PlatformIO with:
 *   lib_deps = file:///../../cblicense
 * or copy the cblicense tree into your project's lib/ directory.
 */

#include <Arduino.h>
#include "cblicense/cblicense.h"

extern "C" const cbl_fingerprint_provider_t *cbl_fp_esp32(void);

/* Replace with your vendor salt. */
static const uint8_t kVendorSalt[CBL_SALT_LEN] = {
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
  0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
  0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

/* Set this to a code minted by `cbl-mint --family plc_firmware
 * --device-id-b32 <printed below>` to skip the runtime prompt. */
static const char *kHardcodedCode = nullptr;

static uint8_t g_device_id[CBL_DEVICE_ID_LEN];

static void print_hex(const uint8_t *bytes, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02x", bytes[i]);
    Serial.print(buf);
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println();
  Serial.println("=== cblicense smoke test ===");
  Serial.print("library: ");
  Serial.println(cbl_version_str());

  const cbl_fingerprint_provider_t *fp = cbl_fp_esp32();
  if (!fp) {
    Serial.println("ERROR: ESP32 fingerprint provider unavailable");
    return;
  }

  cbl_status_t st = cbl_compute_fingerprint(fp, g_device_id);
  if (st != CBL_OK) {
    Serial.print("ERROR: fingerprint failed: ");
    Serial.println(cbl_status_str(st));
    return;
  }

  char encoded[CBL_DEVICE_ID_STR_BUF_LEN];
  cbl_encode_device_id(g_device_id, encoded, sizeof(encoded));
  Serial.print("device fingerprint (b32): ");
  Serial.println(encoded);
  Serial.print("raw sha256: ");
  print_hex(g_device_id, CBL_DEVICE_ID_LEN);
  Serial.println();

  if (kHardcodedCode) {
    st = cbl_verify_short_code(kHardcodedCode, CBL_FAMILY_PLC_FIRMWARE, g_device_id, kVendorSalt);
    Serial.print("verify hardcoded code: ");
    Serial.println(cbl_status_str(st));
    return;
  }

  Serial.println();
  Serial.println("paste a 15-char activation code (XXXXX-XXXXX-XXXXX) and press enter:");
}

void loop() {
  static String input;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (input.length() > 0) {
        cbl_status_t st = cbl_verify_short_code(input.c_str(),
                                                CBL_FAMILY_PLC_FIRMWARE,
                                                g_device_id, kVendorSalt);
        Serial.print("verify: ");
        Serial.println(cbl_status_str(st));
        input = "";
      }
    } else if (input.length() < 64) {
      input += c;
    }
  }
}

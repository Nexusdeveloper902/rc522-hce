/**
 * Rc522HceConfig.h — user configuration for RC522-HCE.
 *
 * NOTHING in this file requires editing library source code. Every knob is
 * `#ifndef`-guarded, so the resolution order is:
 *
 *   1. a build flag you pass (`-DRC522HCE_SS_PIN=13` in platformio.ini
 *      `build_flags`, or `-D` in the Arduino IDE / Makefile) — always wins;
 *   2. the auto-detected board preset below (when your board is recognized);
 *   3. the generic default.
 *
 * So changing pins, timings, the AID or the debounce window is a build-flag
 * change (or a copy of this file if you prefer a per-project header) — never
 * a source edit. The reader reads these at construction, so they also apply
 * to default-constructed readers (`Rc522HceReader radio;`).
 */
#pragma once

#include <stdint.h>  // not <cstdint>: some toolchains ship no C++ stdlib

// ---------------------------------------------------------------------------
// Wiring — RC522 signal pins
// ---------------------------------------------------------------------------
// Auto-detection covers the common boards; override on custom wiring.
// `RC522HCE_RST_PIN` of 255 means RST is strapped to 3V3 (the driver then
// soft-resets only and drives no pin) — useful when pins are scarce or when
// a board's strapping pins misbehave at boot.

#if defined(RC522HCE_NO_BOARD_PRESET)
// Opt out of preset detection and use only the overrides/defaults below.

#elif defined(ARDUINO_ARCH_ESP32) || defined(ESP32)
#define RC522HCE_SS_PIN 5
#define RC522HCE_RST_PIN 27
#define RC522HCE_SCK_PIN 18
#define RC522HCE_MISO_PIN 19
#define RC522HCE_MOSI_PIN 23
#define RC522HCE_PRESET "esp32dev (ESP32 VSPI)"

#elif defined(ARDUINO_ARCH_AVR) && (defined(__AVR_ATmega2560__) || defined(__AVR_ATmega1280__))
#define RC522HCE_SS_PIN 53
#define RC522HCE_RST_PIN 5
#define RC522HCE_SCK_PIN 52
#define RC522HCE_MISO_PIN 50
#define RC522HCE_MOSI_PIN 51
#define RC522HCE_PRESET "megaatmega2560 (Mega hardware SPI)"

#elif defined(ARDUINO_ARCH_AVR)
// ATmega328P and friends (UNO, Nano, Pro Mini): hardware SPI pins are fixed
// and cannot be routed; only SS is freely choosable.
#define RC522HCE_SS_PIN 10
#define RC522HCE_RST_PIN 9
#define RC522HCE_SCK_PIN 13
#define RC522HCE_MISO_PIN 12
#define RC522HCE_MOSI_PIN 11
#define RC522HCE_PRESET "atmega328p (UNO/Nano; SCK/MISO/MOSI are hardware SPI)"

#elif defined(ESP8266)
#define RC522HCE_SS_PIN 15
#define RC522HCE_RST_PIN 5
#define RC522HCE_SCK_PIN 14
#define RC522HCE_MISO_PIN 12
#define RC522HCE_MOSI_PIN 13
#define RC522HCE_PRESET "esp8266 (NodeMCU)"

#elif defined(ARDUINO_ARCH_RP2040)
#define RC522HCE_SS_PIN 17
#define RC522HCE_RST_PIN 20
#define RC522HCE_SCK_PIN 18
#define RC522HCE_MISO_PIN 16
#define RC522HCE_MOSI_PIN 19
#define RC522HCE_PRESET "rp2040 (Raspberry Pi Pico)"

#elif defined(ARDUINO_ARCH_STM32) || defined(STM32F1) || defined(STM32F4)
// STM32duino default SPI1: PA4=SS, PA5=SCK, PA6=MISO, PA7=MOSI.
#define RC522HCE_SS_PIN PA4
#define RC522HCE_RST_PIN PB0
#define RC522HCE_SCK_PIN PA5
#define RC522HCE_MISO_PIN PA6
#define RC522HCE_MOSI_PIN PA7
#define RC522HCE_PRESET "stm32 (SPI1 default)"
#endif

#ifndef RC522HCE_SS_PIN
#define RC522HCE_SS_PIN 5
#endif
#ifndef RC522HCE_RST_PIN
#define RC522HCE_RST_PIN 27
#endif
#ifndef RC522HCE_SCK_PIN
#define RC522HCE_SCK_PIN 18
#endif
#ifndef RC522HCE_MISO_PIN
#define RC522HCE_MISO_PIN 19
#endif
#ifndef RC522HCE_MOSI_PIN
#define RC522HCE_MOSI_PIN 23
#endif

// ---------------------------------------------------------------------------
// The AID your phone's HCE app must serve
// ---------------------------------------------------------------------------
// A comma-separated byte list, so it is overridable from a build flag:
//   -DRC522HCE_AID_BYTES=0xF0,0x01,0x02,0x03,0x04,0x05,0x06
// Changing it breaks every phone app already in the field — change it only
// when you also control the app. 1..11 bytes (the SELECT frame must fit the
// reader's 16-byte command buffer). Alternatively change it at RUNTIME with
// Rc522HceReader::setAid().
#ifndef RC522HCE_AID_BYTES
#define RC522HCE_AID_BYTES 0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
#endif

// ---------------------------------------------------------------------------
// Behavior knobs (also settable in code; these are just the defaults)
// ---------------------------------------------------------------------------

/** Re-read suppression: a card resting on the antenna never re-fires. */
#ifndef RC522HCE_DEBOUNCE_MS
#define RC522HCE_DEBOUNCE_MS 2000
#endif

/** PCD retry + runtime health-probe cadence (ms). */
#ifndef RC522HCE_REINIT_INTERVAL_MS
#define RC522HCE_REINIT_INTERVAL_MS 5000
#endif

/** Park-and-activate radio-silence window before a tap's first RATS (ms). */
#ifndef RC522HCE_HCE_SETTLE_MS
#define RC522HCE_HCE_SETTLE_MS 400
#endif

/**
 * SPI clock for the RC522 bus. The MFRC522 library reads this macro, so it is
 * a plain build flag: -DMFRC522_SPICLOCK=1000000u. Override only if you know
 * your wiring is good enough for more; 1 MHz is the bench-proven value and
 * the speed buys nothing at these frame sizes.
 */
#ifndef MFRC522_SPICLOCK
#define MFRC522_SPICLOCK 1000000u
#endif

/** Name reported by RC522HCE_PRESET-prone logs; useful in a build banner. */
#ifndef RC522HCE_PRESET
#define RC522HCE_PRESET "defaults (no board preset matched)"
#endif

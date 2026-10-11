// HceEnroll — operation taps plus one-shot phone enrollment.
//
// Hold a button (or send 'e' over Serial) to arm enrollment for the next
// tap: the phone hands over its key once (inside its holder-opened
// enrollment window) and the reader wraps it under READER_SECRET before
// it touches the network. The raw key is never printed.
//
// Wiring: see docs/WIRING.md.

#include <Arduino.h>

#include <HceReader.h>
#include <Rc522HceReader.h>

// TODO: provision per device from a CSPRNG (e.g. 16+ random bytes, hex).
// Generate once per reader (e.g. `esp_random` on ESP32, stored in NVS),
// never share across the fleet, never log. Human passwords do NOT qualify:
// a guessable secret lets captured enrollment transcripts be attacked
// offline (see docs/SECURITY.md). Placeholder only — not production entropy.
static const char* READER_SECRET = "change-me-per-device";

#ifdef ESP32
rc522hce::Rc522HceReader radio;
#elif defined(__AVR_ATmega2560__) || defined(__AVR_ATmega1280__)
rc522hce::Rc522HceReader radio(53, 5, 52, 50, 51); // Mega hardware SPI
#else
rc522hce::Rc522HceReader radio(10, 9, 13, 12, 11); // UNO/Nano hardware SPI
#endif
rc522hce::HceReader reader(radio);

void setup() {
    Serial.begin(115200);
    while (!Serial) {
    }
    if (!reader.begin()) {
        Serial.println(F("RC522 not responding — check wiring + 3.3 V"));
    }
    Serial.println(F("Send 'e' + Enter to arm enrollment for the next tap."));
}

void loop() {
    if (Serial.available()) {
        const char c = (char)Serial.read();
        if (c == 'e' || c == 'E') {
            reader.setEnrollment(true, READER_SECRET);
            Serial.println(F("Enrollment ARMED for the next tap."));
        }
    }

    rc522hce::HceReader::Tap tap;
    if (reader.read(tap, millis())) {
        Serial.print(F("Tap: "));
        Serial.println(tap.credentialId.c_str());
        if (tap.isHce && tap.proof.hasKey()) {
            // Enrollment tap: POST credentialId + nonceHex + macHex +
            // keyWrappedHex + keyNonceHex to your server, then disarm.
            // The raw phone key never appears here by construction.
            Serial.println(F("  enrolled — wrapped key ready for the server"));
            reader.setEnrollment(false);
        } else if (tap.isHce) {
            Serial.println(F("  operation tap — relay nonce+mac to the server"));
        }
    }
}

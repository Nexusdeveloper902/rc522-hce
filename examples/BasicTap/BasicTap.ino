// BasicTap — the minimal app: print every tap's credential id.
//
// Wiring: see docs/WIRING.md. ESP32 DevKit uses the constructor defaults;
// UNO/Nano and other boards pass their pins explicitly.

#include <Arduino.h>

#include <HceReader.h>
#include <Rc522HceReader.h>

#ifdef ESP32
rc522hce::Rc522HceReader radio;                    // DevKit VSPI defaults
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
    } else {
        Serial.print(F("Reader ready: "));
        Serial.println(reader.label());
    }
}

void loop() {
    rc522hce::HceReader::Tap tap;
    // Phone taps: hold the phone flat ~2-3 cm above the sensor and keep it
    // still until the tap prints — an HCE tap takes ~half a second.
    if (reader.read(tap, millis())) {
        Serial.print(tap.isHce ? F("HCE credential: ") : F("Card UID: "));
        Serial.println(tap.credentialId.c_str());
        if (tap.isHce) {
            // Relay these two to your server; it verifies
            // HMAC-SHA256(K_cred, credId || nonce) == mac.
            Serial.print(F("  nonce: "));
            Serial.println(tap.proof.nonceHex.c_str());
            Serial.print(F("  mac:   "));
            Serial.println(tap.proof.macHex.c_str());
        }
    }
    if (!reader.healthy()) {
        // Radio stopped answering at runtime — the driver is already
        // retrying on its reinit cadence; this line is just visibility.
        Serial.println(F("Reader degraded — retrying…"));
        delay(1000);
    }
}

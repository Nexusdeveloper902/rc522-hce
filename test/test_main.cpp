/**
 * test_main.cpp — the single native-test entry point.
 *
 * PlatformIO's native environment links every test/*.cpp into ONE
 * program, so exactly one main() lives here; each test file exposes a
 * registrar that queues its RUN_TEST calls.
 *
 * On Arduino (`pio test -e esp32test`) the same file provides
 * setup()/loop() instead — PlatformIO's Arduino core supplies main().
 * The HIL suite (test_hil_radio.cpp) only exists there (host files are
 * pure C++ and compile for the MCU too, which is itself a portability
 * check).
 */
#include <unity.h>

void runHceApduTests();
void runHceCryptoTests();
void runIsoDepFrameTests();
void runDebouncerTests();
void runReaderContractTests();
void runFacadeTests();
void runPublicApiTests();
void runConfigTests();
#ifdef ARDUINO
void runHilTests();
#endif

// Shared by every test (Unity calls these around each RUN_TEST).
void setUp() {}
void tearDown() {}

static void runAllTests() {
    runHceApduTests();       // APDU builders/parsers: the wire contract
    runHceCryptoTests();     // SHA-256 / HMAC / key-wrap: the trust contract
    runIsoDepFrameTests();   // SAK + PCB + I-block strip + resync: the RF contract
    runDebouncerTests();     // tap debounce: one event per physical tap
    runReaderContractTests();  // NfcReader/mock + simulated end-to-end taps
    runFacadeTests();          // HceReader: the public configure-and-read API
    runPublicApiTests();       // the exposed protocol surface (one include only)
    runConfigTests();          // build-flag config, AID override, legacy aliases
#ifdef ARDUINO
    runHilTests();  // on-device: vector, RNG, live radio probe (ignores gracefully unwired)
#endif
}

#ifdef ARDUINO
#include <Arduino.h>

void setup() {
    UNITY_BEGIN();
    runAllTests();
    UNITY_END();
}

void loop() {
    delay(1000);  // results printed once in setup(); idle here
}

#else

int main() {
    UNITY_BEGIN();
    runAllTests();
    return UNITY_END();
}

#endif

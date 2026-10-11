/**
 * test_main.cpp — the single native-test entry point.
 *
 * PlatformIO's native environment links every test/*.cpp into ONE
 * program, so exactly one main() lives here; each test file exposes a
 * registrar that queues its RUN_TEST calls.
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

// Shared by every test (Unity calls these around each RUN_TEST).
void setUp() {}
void tearDown() {}

int main() {
    UNITY_BEGIN();

    runHceApduTests();       // APDU builders/parsers: the wire contract
    runHceCryptoTests();     // SHA-256 / HMAC / key-wrap: the trust contract
    runIsoDepFrameTests();   // SAK + PCB + I-block strip + resync: the RF contract
    runDebouncerTests();     // tap debounce: one event per physical tap
    runReaderContractTests();  // NfcReader/mock + simulated end-to-end taps
    runFacadeTests();          // HceReader: the public configure-and-read API
    runPublicApiTests();       // the exposed protocol surface (one include only)
    runConfigTests();          // build-flag config, AID override, legacy aliases

    return UNITY_END();
}

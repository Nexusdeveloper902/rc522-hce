/**
 * test_hil_radio.cpp — hardware-in-the-loop tests (device only).
 *
 * These run ON a board with a wired RC522 (`pio test -e esp32test` with
 * the board attached); they are compile-checked in CI without hardware
 * (`hil-build` job) so they cannot rot silently.
 *
 * What HIL covers that host tests cannot: the real toolchain's codegen
 * and endianness (crypto vector on-MCU), the real RNG (two nonces
 * differ), and the radio driver's probe/poll contract against live
 * hardware. RF assertions degrade gracefully: without a wired RC522
 * they TEST_IGNORE instead of failing, so a bare board still checks
 * the crypto + RNG paths.
 *
 * Procedure: wire per docs/WIRING.md, attach the board, remove all
 * cards/phones from the antenna, then `pio test -e esp32test`.
 */
#ifdef ARDUINO

#include <unity.h>

#include <Arduino.h>

#include <cstring>  // memset/memcmp in the HIL checks

#include "HceReader.h"
#include "Rc522HceReader.h"

using namespace rc522hce;

static Rc522HceReader s_radio;
static HceReader s_reader(s_radio);

void test_hil_crypto_vector_matches_on_mcu(void) {
    // Toolchain/endianness check: the shared vector must verify on-device.
    TEST_ASSERT_TRUE(HceReader::selfCheckVector());
}

void test_hil_aead_vector_unwraps_on_mcu(void) {
    uint8_t key[KEY_LEN];
    TEST_ASSERT_EQUAL_size_t(KEY_LEN, HceReader::fromHex(TestVector::kKeyHex, key, sizeof(key)));
    uint8_t recovered[KEY_LEN];
    TEST_ASSERT_EQUAL_size_t(KEY_LEN,
                             HceReader::unwrapKeyHex(TestVector::kReaderSecret, TestVector::kCredId,
                                                     TestVector::kKeyNonceHex,
                                                     TestVector::kKeyWrappedHex, recovered));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(key, recovered, KEY_LEN);
    memset(key, 0, sizeof(key));
    memset(recovered, 0, sizeof(recovered));
}

void test_hil_nonce_source_produces_fresh_nonces(void) {
    // Real RNG smoke: two 16-byte nonces must differ (2^-128 flake odds).
    uint8_t a[NONCE_LEN], b[NONCE_LEN];
    fillRandomBytes(a, sizeof(a), defaultRandomWord);
    fillRandomBytes(b, sizeof(b), defaultRandomWord);
    TEST_ASSERT_FALSE(memcmp(a, b, sizeof(a)) == 0);
}

void test_hil_radio_probe_and_idle_poll(void) {
    if (!s_reader.begin()) {
        TEST_IGNORE_MESSAGE("RC522 not wired — crypto/RNG checks above still ran");
    }
    TEST_ASSERT_TRUE(s_reader.healthy());
    TEST_ASSERT_NOT_EQUAL(0x00, s_radio.lastVersion());
    // No card on the antenna: poll must report nothing (not a tap).
    HceReader::Tap tap;
    TEST_ASSERT_FALSE(s_reader.read(tap, millis()));
}

void runHilTests() {
    RUN_TEST(test_hil_crypto_vector_matches_on_mcu);
    RUN_TEST(test_hil_aead_vector_unwraps_on_mcu);
    RUN_TEST(test_hil_nonce_source_produces_fresh_nonces);
    RUN_TEST(test_hil_radio_probe_and_idle_poll);
}

#endif  // ARDUINO

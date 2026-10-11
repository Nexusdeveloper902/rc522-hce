/**
 * test_config.cpp — configuration without touching source.
 *
 * Pins the guarantee the docs make: the reader's defaults come from the
 * config header, so a build flag changes wiring without a source edit. It
 * also pins the config header's own invariants (the part most likely to
 * silently rot), the AID override path, and the optional legacy alias layer.
 */
#include <unity.h>

#include <stdint.h>
#include <cstring>
#include <string>

#include "CompatNames.h"      // also pulls in Rc522HceConfig.h transitively
#include "Rc522HceConfig.h"

using namespace rc522hce;

// --- Config header invariants ---------------------------------------------------

static bool spiSignalPinsCollide() {
    const int pins[4] = {RC522HCE_SS_PIN, RC522HCE_SCK_PIN, RC522HCE_MISO_PIN, RC522HCE_MOSI_PIN};
    for (int i = 0; i < 4; i++) {
        for (int j = i + 1; j < 4; j++) {
            if (pins[i] == pins[j]) {
                return true;
            }
        }
    }
    return false;
}

void test_config_spi_signal_pins_do_not_collide(void) {
    TEST_ASSERT_FALSE(spiSignalPinsCollide());
}

void test_config_defaults_match_the_documented_values(void) {
    // Host build (no Arduino board macros match): the generic defaults apply,
    // and they are the classic ESP32 DevKit VSPI wiring from docs/WIRING.md.
    TEST_ASSERT_EQUAL_INT(5, RC522HCE_SS_PIN);
    TEST_ASSERT_EQUAL_INT(27, RC522HCE_RST_PIN);
    TEST_ASSERT_EQUAL_INT(18, RC522HCE_SCK_PIN);
    TEST_ASSERT_EQUAL_INT(19, RC522HCE_MISO_PIN);
    TEST_ASSERT_EQUAL_INT(23, RC522HCE_MOSI_PIN);
    TEST_ASSERT_EQUAL_INT(2000, RC522HCE_DEBOUNCE_MS);
    TEST_ASSERT_EQUAL_INT32(5000, RC522HCE_REINIT_INTERVAL_MS);
    TEST_ASSERT_EQUAL_INT32(400, RC522HCE_HCE_SETTLE_MS);
    TEST_ASSERT_EQUAL_INT32(1000000, MFRC522_SPICLOCK);
}

void test_config_aid_bytes_are_within_protocol_limits(void) {
    const uint8_t aid[] = {RC522HCE_AID_BYTES};
    TEST_ASSERT_TRUE(sizeof(aid) >= 1);
    TEST_ASSERT_TRUE(sizeof(aid) <= MAX_AID_LEN);
    // The macro and the protocol default must describe the same AID.
    TEST_ASSERT_EQUAL_size_t(AID_LEN, sizeof(aid));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(AID, aid, sizeof(aid));
}

void test_config_aid_builds_the_default_frame(void) {
    uint8_t out[16];
    TEST_ASSERT_EQUAL_size_t(12, buildSelectAid(out, sizeof(out)));
    const uint8_t want[] = {0x00, 0xA4, 0x04, 0x00, 0x07,
                            0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, out, sizeof(want));
}

// --- AID: runtime override, no reflash -------------------------------------------------

void test_custom_aid_builds_the_right_frame(void) {
    // A deployment with its own AID: same builder, different bytes.
    const uint8_t custom[] = {0xD1, 0x76, 0x00, 0x00, 0x85};
    uint8_t out[16];
    const size_t n = buildSelectAidWith(custom, sizeof(custom), out, sizeof(out));

    const uint8_t want[] = {0x00, 0xA4, 0x04, 0x00, 0x05,
                            0xD1, 0x76, 0x00, 0x00, 0x85};
    TEST_ASSERT_EQUAL_size_t(sizeof(want), n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, out, sizeof(want));
}

void test_default_and_custom_aid_produce_different_frames(void) {
    uint8_t a[16], b[16];
    const size_t la = buildSelectAid(a, sizeof(a));
    const uint8_t other[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x00, 0x01};
    const size_t lb = buildSelectAidWith(other, sizeof(other), b, sizeof(b));
    TEST_ASSERT_TRUE(la != 0);
    TEST_ASSERT_TRUE(lb != 0);
    TEST_ASSERT_TRUE(la != lb || memcmp(a, b, la) != 0);
}

void test_aid_length_limits_are_enforced(void) {
    uint8_t out[16];
    const uint8_t one[1] = {0xF0};
    const uint8_t max[MAX_AID_LEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    const uint8_t tooLong[MAX_AID_LEN + 1] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    TEST_ASSERT_EQUAL_size_t(6, buildSelectAidWith(one, 1, out, sizeof(out)));        // minimum
    TEST_ASSERT_EQUAL_size_t(5 + MAX_AID_LEN, buildSelectAidWith(max, MAX_AID_LEN, out, sizeof(out)));
    TEST_ASSERT_EQUAL_size_t(0, buildSelectAidWith(tooLong, sizeof(tooLong), out, sizeof(out)));
    TEST_ASSERT_EQUAL_size_t(0, buildSelectAidWith(nullptr, 4, out, sizeof(out)));
    TEST_ASSERT_EQUAL_size_t(0, buildSelectAidWith(max, 0, out, sizeof(out)));
    // Short buffer refuses rather than truncating a SELECT frame.
    TEST_ASSERT_EQUAL_size_t(0, buildSelectAidWith(max, MAX_AID_LEN, out, 12));
}

// --- Legacy alias layer ---------------------------------------------------------------

void test_compat_names_are_the_same_types(void) {
    // The alias layer must be exact (identical types in both directions),
    // not a copy that needs conversion.
    Presence::HceProof legacy;
    legacy.nonceHex = "0123456789abcdef";
    legacy.macHex = std::string(64, 'a');

    rc522hce::HceProof modern = legacy;            // compiles only if types match
    rc522hce::MockNfcReader mock;
    Presence::MockSerialNfcReader& alias = mock;  // historical name still binds
    Presence::NfcReader* iface = &mock;            // historical interface name binds

    TEST_ASSERT_EQUAL_STRING(legacy.nonceHex.c_str(), modern.nonceHex.c_str());
    TEST_ASSERT_EQUAL_STRING("MOCK (host input)", alias.label());
    TEST_ASSERT_EQUAL_STRING("MOCK (host input)", iface->label());
}

void test_compat_names_protocol_surface_resolves(void) {
    // `Presence::Hce::…` and `Presence::Signer::toHex` must resolve to the same
    // implementation with the same bytes — no second source of truth.
    uint8_t out[16];
    const size_t n = Presence::Hce::buildSelectAid(out, sizeof(out));
    TEST_ASSERT_EQUAL_size_t(12, n);

    uint8_t modern[16];
    TEST_ASSERT_EQUAL_size_t(n, rc522hce::buildSelectAid(modern, sizeof(modern)));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(out, modern, n);

    TEST_ASSERT_EQUAL_STRING("6162", Presence::Signer::toHex((const uint8_t*)"ab", 2).c_str());
    TEST_ASSERT_EQUAL_INT((int)rc522hce::SelectOutcome::Selected,
                          (int)Presence::Hce::parseSelectResponse((const uint8_t*)"HCE-OK\x90\x00", 8));
    TEST_ASSERT_EQUAL_STRING("ba6d0fbf5106f79257727819d19a17b7e15abc4b8a0d1bfe71cd76090488a295",
                             Presence::Hce::TestVector::kMacHex);
}

void runConfigTests() {
    RUN_TEST(test_config_spi_signal_pins_do_not_collide);
    RUN_TEST(test_config_defaults_match_the_documented_values);
    RUN_TEST(test_config_aid_bytes_are_within_protocol_limits);
    RUN_TEST(test_config_aid_builds_the_default_frame);
    RUN_TEST(test_custom_aid_builds_the_right_frame);
    RUN_TEST(test_default_and_custom_aid_produce_different_frames);
    RUN_TEST(test_aid_length_limits_are_enforced);
    RUN_TEST(test_compat_names_are_the_same_types);
    RUN_TEST(test_compat_names_protocol_surface_resolves);
}

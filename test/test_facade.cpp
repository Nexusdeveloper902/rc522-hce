/**
 * test_facade.cpp — HceReader: "configure once, then just read".
 *
 * Pins the only contract normal apps program against: one read() == one
 * physical tap, proof forwarded for HCE taps and cleared otherwise,
 * enrollment forwarded (+ debounce reset), health forwarded. Uses a
 * scripted fake transport so resting-card and cooldown timing are exact.
 */
#include <unity.h>

#include <stdint.h>
#include <string>
#include <vector>

#include "HceReader.h"
#include "MockNfcReader.h"
#include "NfcReader.h"

using namespace rc522hce;

// Scripted transport: each poll() consumes the next scripted slot.
// A slot with `present == false` reports "no credential".
class FakeReader : public NfcReader {
public:
    struct Slot {
        bool present;
        std::string id;
    };

    bool begin() override {
        beginCalls++;
        return beginResult;
    }

    bool poll(std::string& idOut) override {
        if (pollCalls < script.size() && script[pollCalls].present) {
            idOut = script[pollCalls].id;
            pollCalls++;
            return true;
        }
        pollCalls++;
        return false;
    }

    const char* lastKind() const override { return credentialKindName(kind_); }
    CredentialKind kind() const override { return kind_; }
    const HceProof& lastProof() const override { return proof; }

    void setEnrollment(bool on, const std::string& secret) override {
        enrollmentOn = on;
        enrollmentSecret = secret;
    }

    const char* label() const override { return "FAKE"; }
    bool healthy() const override { return healthyFlag; }

    void queue(bool present, const std::string& id = std::string()) {
        script.push_back({present, id});
    }

    std::vector<Slot> script;
    size_t pollCalls = 0;
    int beginCalls = 0;
    bool beginResult = true;
    CredentialKind kind_ = CredentialKind::Physical;
    HceProof proof;
    bool enrollmentOn = false;
    std::string enrollmentSecret;
    bool healthyFlag = true;
};

void test_facade_begin_forwards(void) {
    FakeReader fake;
    HceReader reader(fake);
    TEST_ASSERT_TRUE(reader.begin());
    TEST_ASSERT_EQUAL_INT(1, fake.beginCalls);
    fake.beginResult = false;
    TEST_ASSERT_FALSE(reader.begin());
}

void test_facade_returns_one_tap_per_physical_touch(void) {
    FakeReader fake;
    fake.queue(true, "04A3B2C1");   // tap
    fake.queue(false);              // card still there? no — gone
    HceReader reader(fake);

    HceReader::Tap tap;
    TEST_ASSERT_TRUE(reader.read(tap, 1000));
    TEST_ASSERT_EQUAL_STRING("04A3B2C1", tap.credentialId.c_str());
    TEST_ASSERT_FALSE(tap.isHce);
    TEST_ASSERT_TRUE(tap.kind == CredentialKind::Physical);
    TEST_ASSERT_FALSE(tap.proof.present());
    TEST_ASSERT_FALSE(reader.read(tap, 1100));
}

void test_facade_suppresses_a_resting_card(void) {
    FakeReader fake;
    for (int i = 0; i < 20; i++) {
        fake.queue(true, "04A3B2C1");  // card never leaves the antenna
    }
    HceReader reader(fake);

    HceReader::Tap tap;
    int events = 0;
    for (uint32_t t = 1000; t < 1000 + 20 * 100; t += 100) {
        if (reader.read(tap, t)) {
            events++;
        }
    }
    TEST_ASSERT_EQUAL_INT(1, events);
}

void test_facade_accepts_deliberate_retap_after_absence(void) {
    FakeReader fake;
    fake.queue(true, "04A3B2C1");  // first tap
    fake.queue(false);             // removed
    fake.queue(false);             // still gone
    fake.queue(true, "04A3B2C1");  // deliberate re-tap, past cooldown
    HceReader reader(fake, 2000);

    HceReader::Tap tap;
    TEST_ASSERT_TRUE(reader.read(tap, 1000));
    TEST_ASSERT_FALSE(reader.read(tap, 1100));
    TEST_ASSERT_FALSE(reader.read(tap, 1200));
    TEST_ASSERT_TRUE(reader.read(tap, 3100));
    TEST_ASSERT_EQUAL_STRING("04A3B2C1", tap.credentialId.c_str());
}

void test_facade_accepts_a_different_credential_immediately(void) {
    FakeReader fake;
    fake.queue(true, "CARD-A");
    fake.queue(true, "CARD-B");  // previous one must have left
    HceReader reader(fake);

    HceReader::Tap first, second;
    TEST_ASSERT_TRUE(reader.read(first, 1000));
    TEST_ASSERT_TRUE(reader.read(second, 1100));
    TEST_ASSERT_EQUAL_STRING("CARD-A", first.credentialId.c_str());
    TEST_ASSERT_EQUAL_STRING("CARD-B", second.credentialId.c_str());
}

void test_facade_forwards_hce_identity_and_proof(void) {
    FakeReader fake;
    fake.kind_ = CredentialKind::Hce;
    fake.proof.nonceHex = "000102030405060708090a0b0c0d0e0f";
    fake.proof.macHex = std::string(64, 'a');
    fake.queue(true, "PLS-K3Y7V3CT0R5Z");
    HceReader reader(fake);

    HceReader::Tap tap;
    TEST_ASSERT_TRUE(reader.read(tap, 5000));
    TEST_ASSERT_EQUAL_STRING("PLS-K3Y7V3CT0R5Z", tap.credentialId.c_str());
    TEST_ASSERT_TRUE(tap.isHce);
    TEST_ASSERT_TRUE(tap.kind == CredentialKind::Hce);
    TEST_ASSERT_TRUE(tap.proof.present());
    TEST_ASSERT_EQUAL_STRING("000102030405060708090a0b0c0d0e0f", tap.proof.nonceHex.c_str());
}

// Legacy v1.x custom transports override only the string lastKind().
// The facade must still classify those as HCE (backward compatibility).
class LegacyStringReader : public NfcReader {
public:
    bool begin() override { return true; }
    bool poll(std::string& idOut) override {
        idOut = "PLS-LEGACY";
        return true;
    }
    const char* lastKind() const override { return "hce"; }
    const char* label() const override { return "LEGACY"; }
};

void test_facade_accepts_legacy_string_kind(void) {
    LegacyStringReader legacy;
    HceReader reader(legacy);
    HceReader::Tap tap;
    TEST_ASSERT_TRUE(reader.read(tap, 1000));
    TEST_ASSERT_TRUE(tap.isHce);
    TEST_ASSERT_TRUE(tap.kind == CredentialKind::Hce);
}

void test_credential_kind_names_round_trip(void) {
    TEST_ASSERT_EQUAL_STRING("physical", credentialKindName(CredentialKind::Physical));
    TEST_ASSERT_EQUAL_STRING("hce", credentialKindName(CredentialKind::Hce));
    TEST_ASSERT_TRUE(credentialKindFromString("hce") == CredentialKind::Hce);
    TEST_ASSERT_TRUE(credentialKindFromString("physical") == CredentialKind::Physical);
    TEST_ASSERT_TRUE(credentialKindFromString(nullptr) == CredentialKind::Physical);
    TEST_ASSERT_TRUE(credentialKindFromString("bogus") == CredentialKind::Physical);
}

void test_facade_enrollment_forwards_and_resets_debounce(void) {
    FakeReader fake;
    fake.queue(true, "CARD-A");
    fake.queue(true, "CARD-A");  // resting — would be suppressed…
    fake.queue(true, "CARD-A");  // …third poll, after the mode switch
    HceReader reader(fake);

    HceReader::Tap tap;
    TEST_ASSERT_TRUE(reader.read(tap, 1000));
    TEST_ASSERT_FALSE(reader.read(tap, 1100));

    reader.setEnrollment(true, "reader-secret");  // …but a mode switch resets
    TEST_ASSERT_TRUE(fake.enrollmentOn);
    TEST_ASSERT_EQUAL_STRING("reader-secret", fake.enrollmentSecret.c_str());
    TEST_ASSERT_TRUE(reader.read(tap, 1150));  // accepted again right away

    reader.setEnrollment(false);
    TEST_ASSERT_FALSE(fake.enrollmentOn);
}

void test_facade_forwards_health_and_label(void) {
    FakeReader fake;
    HceReader reader(fake);
    TEST_ASSERT_TRUE(reader.healthy());
    TEST_ASSERT_EQUAL_STRING("FAKE", reader.label());
    fake.healthyFlag = false;  // radio died at runtime
    TEST_ASSERT_FALSE(reader.healthy());
}

void test_facade_works_with_the_mock_transport(void) {
    // The exact object apps use in dev/tests: mock + facade, no hardware.
    MockNfcReader mock;
    HceReader reader(mock);
    TEST_ASSERT_TRUE(reader.begin());

    mock.pushTap("DEV-CARD");
    HceReader::Tap tap;
    TEST_ASSERT_TRUE(reader.read(tap, 100));
    TEST_ASSERT_EQUAL_STRING("DEV-CARD", tap.credentialId.c_str());
    TEST_ASSERT_FALSE(tap.isHce);
    TEST_ASSERT_TRUE(tap.kind == CredentialKind::Physical);
    TEST_ASSERT_FALSE(reader.read(tap, 200));  // consumed
}

void runFacadeTests() {
    RUN_TEST(test_facade_begin_forwards);
    RUN_TEST(test_facade_returns_one_tap_per_physical_touch);
    RUN_TEST(test_facade_suppresses_a_resting_card);
    RUN_TEST(test_facade_accepts_deliberate_retap_after_absence);
    RUN_TEST(test_facade_accepts_a_different_credential_immediately);
    RUN_TEST(test_facade_forwards_hce_identity_and_proof);
    RUN_TEST(test_facade_accepts_legacy_string_kind);
    RUN_TEST(test_credential_kind_names_round_trip);
    RUN_TEST(test_facade_enrollment_forwards_and_resets_debounce);
    RUN_TEST(test_facade_forwards_health_and_label);
    RUN_TEST(test_facade_works_with_the_mock_transport);
}

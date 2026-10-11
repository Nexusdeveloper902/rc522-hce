/**
 * test_public_api.cpp — the exposed protocol surface.
 *
 * This file deliberately includes ONLY <HceReader.h>: if the facade stops
 * re-exporting something the docs promise, this translation unit fails to
 * compile. Beyond the compile-time pin it verifies the runtime behavior a
 * backend depends on: the shared interop vector verifies through the public
 * API, a wrong key/credential/mac does not, and status words are decodable.
 */
#include <unity.h>

#include <cstring>
#include <string>

// THE ONLY include — everything below must be reachable from the facade.
#include "HceReader.h"

using namespace rc522hce;

// --- Compile-time API surface -------------------------------------------------

void test_facade_exposes_the_protocol_surface(void) {
    // Constants the phone app / backend need, straight off the facade.
    TEST_ASSERT_NOT_NULL(HceReader::aid());
    TEST_ASSERT_EQUAL_size_t(7, HceReader::aidLen());
    TEST_ASSERT_EQUAL_UINT8(0xF0, HceReader::aid()[0]);
    TEST_ASSERT_EQUAL_size_t(8, HceReader::nonceLen());
    TEST_ASSERT_EQUAL_size_t(32, HceReader::macLen());
    TEST_ASSERT_EQUAL_size_t(32, HceReader::maxCredentialLen());
    TEST_ASSERT_EQUAL_size_t(32, HceReader::keyLen());

    // Hex helpers exist and round-trip.
    const uint8_t raw[] = {0x00, 0x0F, 0xA5, 0xFF};
    const std::string hex = HceReader::toHex(raw, sizeof(raw));
    TEST_ASSERT_EQUAL_STRING("000fa5ff", hex.c_str());
    uint8_t back[8];
    TEST_ASSERT_EQUAL_size_t(4, HceReader::fromHex(hex, back, sizeof(back)));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(raw, back, sizeof(raw));
}

// --- Shared interop vector, through the public API -----------------------------

static void vectorKey(uint8_t key[32]) {
    TEST_ASSERT_EQUAL_size_t(32, HceReader::fromHex(TestVector::kKeyHex, key, 32));
}

void test_shared_vector_verifies_through_the_public_api(void) {
    // The literal MAC computed outside this implementation, verified by the
    // exported backend check — a new phone app or server must match this.
    uint8_t key[32];
    vectorKey(key);
    TEST_ASSERT_TRUE(HceReader::verifyProof(TestVector::kCredId, TestVector::kNonceHex,
                                            TestVector::kMacHex, key));
    TEST_ASSERT_TRUE(HceReader::selfCheckVector());  // same, via the convenience wrapper

    // And it also verifies when handed the actual proof struct a reader relays.
    HceProof proof;
    proof.nonceHex = TestVector::kNonceHex;
    proof.macHex = TestVector::kMacHex;
    TEST_ASSERT_TRUE(HceReader::verifyProof(proof, TestVector::kCredId, key));
    memset(key, 0, sizeof(key));
}

void test_shared_vector_constants_stay_self_consistent(void) {
    uint8_t key[32];
    vectorKey(key);
    // MAC must be derivable from the vector key/cred/nonce, not just hardcoded.
    uint8_t msg[64];
    memcpy(msg, TestVector::kCredId, strlen(TestVector::kCredId));
    const size_t credLen = strlen(TestVector::kCredId);
    uint8_t nonce[8];
    TEST_ASSERT_EQUAL_size_t(8, HceReader::fromHex(TestVector::kNonceHex, nonce, sizeof(nonce)));
    memcpy(msg + credLen, nonce, 8);
    uint8_t mac[32];
    hmacSha256(key, 32, msg, credLen + 8, mac);
    TEST_ASSERT_EQUAL_STRING(TestVector::kMacHex, HceReader::toHex(mac, 32).c_str());
    memset(msg, 0, sizeof(msg));
    memset(key, 0, sizeof(key));
}

// --- Rejection: verification must fail closed -------------------------------------

void test_verification_fails_closed(void) {
    uint8_t key[32];
    vectorKey(key);
    const std::string cred = TestVector::kCredId;
    const std::string nonce = TestVector::kNonceHex;
    const std::string mac = TestVector::kMacHex;

    key[0] ^= 0x01;  // wrong per-credential key
    TEST_ASSERT_FALSE(HceReader::verifyProof(cred, nonce, mac, key));
    key[0] ^= 0x01;

    TEST_ASSERT_FALSE(HceReader::verifyProof("PLS-SOMEONE-ELSE", nonce, mac, key));  // wrong id
    TEST_ASSERT_FALSE(HceReader::verifyProof(cred, "ffeeddccbbaa9988", mac, key));   // wrong nonce

    std::string flipped = mac;
    flipped[0] = (flipped[0] == 'a') ? 'b' : 'a';  // one hex digit of the MAC
    TEST_ASSERT_FALSE(HceReader::verifyProof(cred, nonce, flipped, key));

    // Malformed transcripts: bad hex, odd length, wrong nonce length, empty,
    // impossible credential id — none may verify.
    TEST_ASSERT_FALSE(HceReader::verifyProof(cred, "zzzz", mac, key));
    TEST_ASSERT_FALSE(HceReader::verifyProof(cred, nonce, mac.substr(0, 63), key));
    TEST_ASSERT_FALSE(HceReader::verifyProof(cred, "abcd", mac, key));
    TEST_ASSERT_FALSE(HceReader::verifyProof("", nonce, mac, key));
    TEST_ASSERT_FALSE(HceReader::verifyProof(std::string(33, 'A'), nonce, "01", key));

    // A proof struct that never got filled is not a proof.
    HceProof empty;
    TEST_ASSERT_FALSE(HceReader::verifyProof(empty, cred, key));
    memset(key, 0, sizeof(key));
}

void test_hex_decode_rejects_garbage(void) {
    uint8_t out[16];
    // Odd length, non-hex chars, wrong case mixes are fine only when valid.
    TEST_ASSERT_EQUAL_size_t(0, HceReader::fromHex("abc", out, sizeof(out)));
    TEST_ASSERT_EQUAL_size_t(0, HceReader::fromHex("zzzz", out, sizeof(out)));
    TEST_ASSERT_EQUAL_size_t(0, HceReader::fromHex("", out, sizeof(out)));
    TEST_ASSERT_EQUAL_size_t(1, HceReader::fromHex("aB", out, sizeof(out)));  // 2 chars = 1 byte
    TEST_ASSERT_EQUAL_UINT8(0xAB, out[0]);
    // Buffer too small: refuses rather than truncating.
    TEST_ASSERT_EQUAL_size_t(0, HceReader::fromHex("00112233", out, 1));
    TEST_ASSERT_EQUAL_size_t(4, HceReader::fromHex("00112233", out, sizeof(out)));
}

// --- Status words ----------------------------------------------------------------

void test_status_words_are_decodable(void) {
    TEST_ASSERT_NOT_NULL(HceReader::statusWordName(0x90, 0x00));
    TEST_ASSERT_NOT_NULL(HceReader::statusWordName(0x6A, 0x82));  // phone routed no app to our AID
    TEST_ASSERT_NOT_NULL(HceReader::statusWordName(0x6A, 0x88));  // phone has no key yet
    TEST_ASSERT_NOT_NULL(HceReader::statusWordName(0x69, 0x85));  // enrollment window closed
    TEST_ASSERT_NOT_NULL(HceReader::statusWordName(0x67, 0x00));
    TEST_ASSERT_NOT_NULL(HceReader::statusWordName(0x6D, 0x00));
    TEST_ASSERT_NOT_NULL(HceReader::statusWordName(0x6E, 0x00));
    TEST_ASSERT_NULL(HceReader::statusWordName(0x12, 0x34));  // unrecognized
}

void test_key_missing_status_round_trips(void) {
    // The reader detects 6A88 off the wire; the API names it for the operator.
    const uint8_t noKey[] = {0x6A, 0x88};
    TEST_ASSERT_TRUE(isKeyMissing(noKey, sizeof(noKey)));
    TEST_ASSERT_NOT_NULL(HceReader::statusWordName(noKey[0], noKey[1]));
}

// --- Enrollment wrapping is part of the exposed surface ------------------------------

void test_enrollment_key_wrap_is_exposed_and_round_trips(void) {
    uint8_t key[32];
    vectorKey(key);
    const std::string wrapped = wrapKeyHex(TestVector::kReaderSecret, TestVector::kCredId,
                                           TestVector::kKeyNonceHex, key);
    TEST_ASSERT_EQUAL_STRING(TestVector::kKeyWrappedHex, wrapped.c_str());

    // Unwrap with the pad the server derives from the same reader secret.
    const std::string label = std::string("pulse-hce-key-wrap/v1\n") + TestVector::kCredId +
                              "\n" + TestVector::kKeyNonceHex;
    uint8_t pad[32];
    hmacSha256(reinterpret_cast<const uint8_t*>(TestVector::kReaderSecret),
               strlen(TestVector::kReaderSecret),
               reinterpret_cast<const uint8_t*>(label.data()), label.size(), pad);
    uint8_t out[32];
    TEST_ASSERT_EQUAL_size_t(32, HceReader::fromHex(wrapped, out, sizeof(out)));
    uint8_t recovered[32];
    for (int i = 0; i < 32; i++) {
        recovered[i] = (uint8_t)(out[i] ^ pad[i]);
    }
    TEST_ASSERT_EQUAL_UINT8_ARRAY(key, recovered, 32);
    memset(key, 0, sizeof(key));
    memset(pad, 0, sizeof(pad));
}

void runPublicApiTests() {
    RUN_TEST(test_facade_exposes_the_protocol_surface);
    RUN_TEST(test_shared_vector_verifies_through_the_public_api);
    RUN_TEST(test_shared_vector_constants_stay_self_consistent);
    RUN_TEST(test_verification_fails_closed);
    RUN_TEST(test_hex_decode_rejects_garbage);
    RUN_TEST(test_status_words_are_decodable);
    RUN_TEST(test_key_missing_status_round_trips);
    RUN_TEST(test_enrollment_key_wrap_is_exposed_and_round_trips);
}

/**
 * test_hce_crypto.cpp — SHA-256 / HMAC-SHA256 / key-wrap contract.
 *
 * The phone, the reader relay and the server verifier must agree
 * bit-for-bit. These tests pin our compact implementation against RFC
 * vectors, FIPS vectors and the shared interop vector (computed outside
 * this code with Python hmac), plus the tamper properties the security
 * model relies on (wrong key/nonce/credential => different MAC).
 */
#include <unity.h>

#include <cstring>
#include <string>

#include "HceProtocol.h"

using namespace rc522hce;

static void vectorKey(uint8_t key[32]) {
    for (int i = 0; i < 32; i++) {
        key[i] = static_cast<uint8_t>(i);
    }
}

static const char kVectorCred[] = "PLS-K3Y7V3CT0R5Z";
static const uint8_t kVectorNonce[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
static const uint8_t kVectorMac[32] = {
    0xba, 0x6d, 0x0f, 0xbf, 0x51, 0x06, 0xf7, 0x92, 0x57, 0x72, 0x78, 0x19, 0xd1, 0x9a, 0x17, 0xb7,
    0xe1, 0x5a, 0xbc, 0x4b, 0x8a, 0x0d, 0x1b, 0xfe, 0x71, 0xcd, 0x76, 0x09, 0x04, 0x88, 0xa2, 0x95};

// --- SHA-256 known answers (FIPS 180-4) -----------------------------------------

void test_sha256_empty_string(void) {
    uint8_t out[32];
    sha256Bytes(nullptr, 0, out);
    TEST_ASSERT_EQUAL_STRING("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                             toHex(out, 32).c_str());
}

void test_sha256_abc(void) {
    uint8_t out[32];
    sha256Bytes(reinterpret_cast<const uint8_t*>("abc"), 3, out);
    TEST_ASSERT_EQUAL_STRING("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                             toHex(out, 32).c_str());
}

void test_sha256_hex_of_body_matches_known_digest(void) {
    // sha256("hello") — guards the toHex + sha256Hex plumbing end to end.
    TEST_ASSERT_EQUAL_STRING("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                             sha256Hex("hello").c_str());
    TEST_ASSERT_EQUAL_UINT32(64, (uint32_t)sha256Hex("").size());
}

void test_sha256_is_binary_safe(void) {
    // Embedded NULs must not truncate the hash input.
    const std::string withNul("AB\x00"
                              "CD",
                              5);
    TEST_ASSERT_TRUE(sha256Hex(withNul) != sha256Hex("ABCD"));
}

// --- HMAC-SHA256 ------------------------------------------------------------------

void test_hmac_matches_rfc4231_case1(void) {
    // RFC 4231 test case 1: key = 20 x 0x0b, data = "Hi There".
    uint8_t key[20];
    memset(key, 0x0b, sizeof(key));
    static const uint8_t data[] = "Hi There";
    uint8_t mac[32];
    hmacSha256(key, sizeof(key), data, sizeof(data) - 1, mac);
    static const uint8_t want[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
        0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
        0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, mac, sizeof(want));
}

void test_hmac_matches_rfc4231_case2(void) {
    // RFC 4231 test case 2: key = "Jefe", data = "what do ya want for nothing?".
    static const uint8_t key[] = "Jefe";
    static const uint8_t data[] = "what do ya want for nothing?";
    uint8_t mac[32];
    hmacSha256(key, 4, data, sizeof(data) - 1, mac);
    TEST_ASSERT_EQUAL_STRING("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                             toHex(mac, 32).c_str());
}

void test_hmac_shared_vector_is_the_phone_answer(void) {
    // Independent of the parser: the HMAC primitive under the vector key
    // reproduces the literal MAC bytes the phone put on the wire.
    uint8_t key[32];
    vectorKey(key);
    uint8_t msg[16 + 8];
    memcpy(msg, kVectorCred, 16);
    memcpy(msg + 16, kVectorNonce, 8);
    uint8_t mac[32];
    hmacSha256(key, 32, msg, sizeof(msg), mac);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kVectorMac, mac, 32);
}

void test_hmac_wrong_key_nonce_or_credential_changes_the_mac(void) {
    uint8_t key[32];
    vectorKey(key);
    uint8_t msg[24];
    uint8_t mac[32];

    memcpy(msg, kVectorCred, 16);
    memcpy(msg + 16, kVectorNonce, 8);

    key[0] ^= 0x01;  // wrong key
    hmacSha256(key, 32, msg, 24, mac);
    TEST_ASSERT_FALSE(memcmp(mac, kVectorMac, 32) == 0);
    key[0] ^= 0x01;

    msg[23] ^= 0x01;  // wrong nonce
    hmacSha256(key, 32, msg, 24, mac);
    TEST_ASSERT_FALSE(memcmp(mac, kVectorMac, 32) == 0);
    msg[23] ^= 0x01;

    msg[15] = 'Y';  // another credential id
    hmacSha256(key, 32, msg, 24, mac);
    TEST_ASSERT_FALSE(memcmp(mac, kVectorMac, 32) == 0);
}

void test_hmac_long_key_hashes_down_per_rfc2104(void) {
    // Keys longer than the 64-byte block hash down first; a 65-byte key of
    // 0xAA must NOT behave like its first 64 bytes.
    uint8_t longKey[65];
    memset(longKey, 0xAA, sizeof(longKey));
    uint8_t shortKey[64];
    memset(shortKey, 0xAA, sizeof(shortKey));
    static const uint8_t msg[] = "test message";
    uint8_t macLong[32], macShort[32];
    hmacSha256(longKey, sizeof(longKey), msg, sizeof(msg) - 1, macLong);
    hmacSha256(shortKey, sizeof(shortKey), msg, sizeof(msg) - 1, macShort);
    TEST_ASSERT_FALSE(memcmp(macLong, macShort, 32) == 0);
}

void test_hmac_empty_key_and_message_do_not_crash(void) {
    uint8_t mac[32];
    hmacSha256(nullptr, 0, nullptr, 0, mac);
    TEST_ASSERT_EQUAL_UINT32(32, (uint32_t)sizeof(mac));
    // Deterministic: same empty inputs => same MAC.
    uint8_t mac2[32];
    hmacSha256(nullptr, 0, nullptr, 0, mac2);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(mac, mac2, 32);
}

// --- Key wrap (pairing) -------------------------------------------------------------

void test_key_wrap_matches_the_shared_vector(void) {
    // Same literal the server test pins: reader key
    // "test-secret-000000000000000001", key nonce 000102..0f.
    uint8_t key[32];
    vectorKey(key);
    const std::string wrapped = wrapKeyHex(
        "test-secret-000000000000000001", kVectorCred, "000102030405060708090a0b0c0d0e0f", key);
    TEST_ASSERT_EQUAL_STRING("c5bb9fe15dff66a8636366dd4e73e0a3146601e3b3c36472961de142a9a914c2",
                             wrapped.c_str());
}

void test_key_wrap_is_bound_to_reader_credential_and_nonce(void) {
    uint8_t key[32];
    vectorKey(key);
    const std::string base = wrapKeyHex(
        "test-secret-000000000000000001", kVectorCred, "000102030405060708090a0b0c0d0e0f", key);
    TEST_ASSERT_TRUE(base != wrapKeyHex("another-reader-key", kVectorCred,
                                        "000102030405060708090a0b0c0d0e0f", key));
    TEST_ASSERT_TRUE(base != wrapKeyHex("test-secret-000000000000000001", "PLS-000000000000",
                                        "000102030405060708090a0b0c0d0e0f", key));
    TEST_ASSERT_TRUE(base != wrapKeyHex("test-secret-000000000000000001", kVectorCred,
                                        "ffffffffffffffffffffffffffffffff", key));
    // Never the key itself.
    TEST_ASSERT_TRUE(base != toHex(key, 32));
}

void test_key_wrap_is_deterministic_and_reversible(void) {
    // Same inputs => same wrap; XOR with the same pad recovers the key
    // (this is exactly what the server does to unwrap).
    uint8_t key[32];
    vectorKey(key);
    const std::string a = wrapKeyHex("s3cret", "CRED-1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key);
    const std::string b = wrapKeyHex("s3cret", "CRED-1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key);
    TEST_ASSERT_EQUAL_STRING(a.c_str(), b.c_str());
    TEST_ASSERT_EQUAL_UINT32(64, (uint32_t)a.size());

    // Round-trip: unwrap with the same pad.
    const std::string label = std::string("pulse-hce-key-wrap/v1\n") + "CRED-1\n" +
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint8_t pad[32];
    hmacSha256(reinterpret_cast<const uint8_t*>("s3cret"), 6,
               reinterpret_cast<const uint8_t*>(label.data()), label.size(), pad);
    uint8_t recovered[32];
    for (int i = 0; i < 32; i++) {
        unsigned hi = a[2 * i] >= 'a' ? (unsigned)(a[2 * i] - 'a' + 10) : (unsigned)(a[2 * i] - '0');
        unsigned lo = a[2 * i + 1] >= 'a' ? (unsigned)(a[2 * i + 1] - 'a' + 10) : (unsigned)(a[2 * i + 1] - '0');
        recovered[i] = (uint8_t)((hi << 4) | lo) ^ pad[i];
    }
    TEST_ASSERT_EQUAL_UINT8_ARRAY(key, recovered, 32);
}

void test_key_wrap_null_key_is_empty(void) {
    TEST_ASSERT_TRUE(wrapKeyHex("s", "c", "n", nullptr).empty());
}

// --- Portable RNG seam (fillRandomBytes) -------------------------------------------
// The driver fills every nonce through this function, so its byte layout is
// pinned here with a deterministic stub — on-device it is fed by esp_random
// (ESP32), the auto-seeded fallback, or an app-injected noise source.

static uint32_t stubWordA(void) { return 0x04030201u; }
static int g_stubCalls = 0;
static uint32_t stubWordSeq(void) {
    static const uint32_t words[] = {0x04030201u, 0x08070605u, 0x0C0B0A09u, 0x100F0E0Du};
    return words[(g_stubCalls++) % 4];
}

void test_fill_random_bytes_is_little_endian_per_word(void) {
    uint8_t out[4] = {0};
    fillRandomBytes(out, sizeof(out), stubWordA);
    const uint8_t want[] = {0x01, 0x02, 0x03, 0x04};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, out, sizeof(want));
}

void test_fill_random_bytes_spans_words_for_nonce_lengths(void) {
    // 8-byte CHALLENGE nonce + 16-byte wrap nonce: multi-word fill, exact bytes.
    g_stubCalls = 0;
    uint8_t nonce[8] = {0};
    fillRandomBytes(nonce, sizeof(nonce), stubWordSeq);
    const uint8_t want8[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want8, nonce, sizeof(nonce));

    uint8_t keyNonce[16] = {0};
    fillRandomBytes(keyNonce, sizeof(keyNonce), stubWordSeq);
    const uint8_t want16[] = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want16, keyNonce, sizeof(keyNonce));
}

void test_fill_random_bytes_handles_partial_tail_and_nulls(void) {
    uint8_t out[6] = {0};  // not a multiple of 4: 4 + 2 tail bytes
    fillRandomBytes(out, sizeof(out), stubWordA);
    const uint8_t want[] = {0x01, 0x02, 0x03, 0x04, 0x01, 0x02};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, out, sizeof(out));

    fillRandomBytes(nullptr, 8, stubWordA);  // must not crash
    uint8_t buf[4] = {0xAA, 0xAA, 0xAA, 0xAA};
    fillRandomBytes(buf, sizeof(buf), nullptr);  // null source: buffer untouched
    const uint8_t untouched[] = {0xAA, 0xAA, 0xAA, 0xAA};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(untouched, buf, sizeof(buf));
}

void runHceCryptoTests() {
    RUN_TEST(test_sha256_empty_string);
    RUN_TEST(test_sha256_abc);
    RUN_TEST(test_sha256_hex_of_body_matches_known_digest);
    RUN_TEST(test_sha256_is_binary_safe);
    RUN_TEST(test_hmac_matches_rfc4231_case1);
    RUN_TEST(test_hmac_matches_rfc4231_case2);
    RUN_TEST(test_hmac_shared_vector_is_the_phone_answer);
    RUN_TEST(test_hmac_wrong_key_nonce_or_credential_changes_the_mac);
    RUN_TEST(test_hmac_long_key_hashes_down_per_rfc2104);
    RUN_TEST(test_hmac_empty_key_and_message_do_not_crash);
    RUN_TEST(test_key_wrap_matches_the_shared_vector);
    RUN_TEST(test_key_wrap_is_bound_to_reader_credential_and_nonce);
    RUN_TEST(test_key_wrap_is_deterministic_and_reversible);
    RUN_TEST(test_key_wrap_null_key_is_empty);
    RUN_TEST(test_fill_random_bytes_is_little_endian_per_word);
    RUN_TEST(test_fill_random_bytes_spans_words_for_nonce_lengths);
    RUN_TEST(test_fill_random_bytes_handles_partial_tail_and_nulls);
}

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
static const uint8_t kVectorNonce[NONCE_LEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const uint8_t kVectorMac[32] = {
    0x70, 0xf3, 0x2d, 0x7b, 0x45, 0x81, 0x39, 0xd8, 0xf5, 0xf5, 0x22, 0xa7, 0x31, 0x4c, 0x31, 0x20,
    0x5e, 0xca, 0x50, 0x61, 0x9a, 0x5d, 0x26, 0xdc, 0x46, 0x6d, 0x7d, 0x5b, 0x60, 0xaa, 0xb1, 0x54};

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
    uint8_t msg[16 + NONCE_LEN];
    memcpy(msg, kVectorCred, 16);
    memcpy(msg + 16, kVectorNonce, NONCE_LEN);
    uint8_t mac[32];
    hmacSha256(key, 32, msg, sizeof(msg), mac);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kVectorMac, mac, 32);
}

void test_hmac_wrong_key_nonce_or_credential_changes_the_mac(void) {
    uint8_t key[32];
    vectorKey(key);
    uint8_t msg[16 + NONCE_LEN];
    uint8_t mac[32];

    memcpy(msg, kVectorCred, 16);
    memcpy(msg + 16, kVectorNonce, NONCE_LEN);

    key[0] ^= 0x01;  // wrong key
    hmacSha256(key, 32, msg, sizeof(msg), mac);
    TEST_ASSERT_FALSE(memcmp(mac, kVectorMac, 32) == 0);
    key[0] ^= 0x01;

    msg[sizeof(msg) - 1] ^= 0x01;  // wrong nonce
    hmacSha256(key, 32, msg, sizeof(msg), mac);
    TEST_ASSERT_FALSE(memcmp(mac, kVectorMac, 32) == 0);
    msg[sizeof(msg) - 1] ^= 0x01;

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
    // Same literal the server test pins (computed outside this code with
    // an independent ChaCha20-Poly1305): reader key
    // "test-secret-000000000000000001", key nonce 12 bytes 00..0b.
    uint8_t key[32];
    vectorKey(key);
    const std::string wrapped = wrapKeyHex(
        "test-secret-000000000000000001", kVectorCred, "000102030405060708090a0b", key);
    TEST_ASSERT_EQUAL_STRING("000102030405060708090a0bd525e39925f68721c72478ce0d25a8078efb99ee6974f2cd8dad8c872882faa4dfcb78880fbc7ee165be05086565530e",
                             wrapped.c_str());
    TEST_ASSERT_EQUAL_UINT32(120, (uint32_t)wrapped.size());  // 24 + 64 + 32
}

void test_key_wrap_is_bound_to_reader_credential_and_nonce(void) {
    uint8_t key[32];
    vectorKey(key);
    const std::string base = wrapKeyHex(
        "test-secret-000000000000000001", kVectorCred, "000102030405060708090a0b", key);
    TEST_ASSERT_TRUE(base != wrapKeyHex("another-reader-key", kVectorCred,
                                        "000102030405060708090a0b", key));
    TEST_ASSERT_TRUE(base != wrapKeyHex("test-secret-000000000000000001", "PLS-000000000000",
                                        "000102030405060708090a0b", key));
    TEST_ASSERT_TRUE(base != wrapKeyHex("test-secret-000000000000000001", kVectorCred,
                                        "ffffffffffffffffffffffff", key));
    // Never the key itself.
    TEST_ASSERT_TRUE(base != toHex(key, 32));
}

void test_key_wrap_is_deterministic_and_reversible(void) {
    // Same inputs => same wrap; AEAD-decrypt with the same secret recovers
    // the key (this is exactly what the server does to unwrap).
    uint8_t key[32];
    vectorKey(key);
    const std::string a = wrapKeyHex("s3cret", "CRED-1", "aaaaaaaaaaaaaaaaaaaaaaaa", key);
    const std::string b = wrapKeyHex("s3cret", "CRED-1", "aaaaaaaaaaaaaaaaaaaaaaaa", key);
    TEST_ASSERT_EQUAL_STRING(a.c_str(), b.c_str());
    TEST_ASSERT_EQUAL_UINT32(120, (uint32_t)a.size());

    uint8_t recovered[32];
    TEST_ASSERT_EQUAL_size_t(32, unwrapKeyHex("s3cret", "CRED-1", "aaaaaaaaaaaaaaaaaaaaaaaa",
                                              a, recovered));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(key, recovered, 32);
    memset(recovered, 0, sizeof(recovered));
    memset(key, 0, sizeof(key));
}

void test_key_wrap_rejects_malformed_inputs(void) {
    uint8_t key[32];
    vectorKey(key);
    TEST_ASSERT_TRUE(wrapKeyHex("s", "c", "n", nullptr).empty());  // null key
    TEST_ASSERT_TRUE(wrapKeyHex("s", "c", "zzzz", key).empty());   // bad nonce hex
    TEST_ASSERT_TRUE(wrapKeyHex("s", "c", "aabbcc", key).empty());  // short nonce (3 B, not 12)
    TEST_ASSERT_TRUE(wrapKeyHex("s", "c", "000102030405060708090a0b0c0d0e0f", key).empty());  // 16 B, not 12
}

void test_key_unwrap_fails_closed_on_tamper(void) {
    // AEAD: any tampering or wrong secret fails closed (tag check) —
    // the v1 construction's silent-corruption class is gone.
    uint8_t key[32];
    vectorKey(key);
    const std::string wrapped = wrapKeyHex(
        "test-secret-000000000000000001", kVectorCred, "000102030405060708090a0b", key);
    uint8_t out[32];
    TEST_ASSERT_EQUAL_size_t(32, unwrapKeyHex("test-secret-000000000000000001", kVectorCred,
                                              "000102030405060708090a0b", wrapped, out));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(key, out, 32);
    // Wrong secret.
    memset(out, 0xAA, sizeof(out));
    TEST_ASSERT_EQUAL_size_t(0, unwrapKeyHex("wrong-secret", kVectorCred,
                                             "000102030405060708090a0b", wrapped, out));
    // Flipped ciphertext byte.
    std::string flipped = wrapped;
    flipped[30] = (flipped[30] == 'a') ? 'b' : 'a';
    memset(out, 0xAA, sizeof(out));
    TEST_ASSERT_EQUAL_size_t(0, unwrapKeyHex("test-secret-000000000000000001", kVectorCred,
                                             "000102030405060708090a0b", flipped, out));
    // Flipped tag byte.
    std::string badTag = wrapped;
    badTag[100] = (badTag[100] == 'a') ? 'b' : 'a';
    TEST_ASSERT_EQUAL_size_t(0, unwrapKeyHex("test-secret-000000000000000001", kVectorCred,
                                             "000102030405060708090a0b", badTag, out));
    // Spliced nonce (leading nonce must match the out-of-band keyNonceHex).
    TEST_ASSERT_EQUAL_size_t(0, unwrapKeyHex("test-secret-000000000000000001", kVectorCred,
                                             "ffffffffffffffffffffffff", wrapped, out));
    // Malformed shape / null out.
    TEST_ASSERT_EQUAL_size_t(0, unwrapKeyHex("test-secret-000000000000000001", kVectorCred,
                                             "000102030405060708090a0b", "zzzz", out));
    TEST_ASSERT_EQUAL_size_t(0, unwrapKeyHex("test-secret-000000000000000001", kVectorCred,
                                             "000102030405060708090a0b",
                                             wrapped.substr(0, 118), out));
    TEST_ASSERT_EQUAL_size_t(0, unwrapKeyHex("s", "c", "n", wrapped, nullptr));
    memset(key, 0, sizeof(key));
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
    // 16-byte CHALLENGE nonce + 12-byte wrap nonce: multi-word fill, exact bytes.
    g_stubCalls = 0;
    uint8_t nonce[NONCE_LEN] = {0};
    fillRandomBytes(nonce, sizeof(nonce), stubWordSeq);
    const uint8_t want16[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want16, nonce, sizeof(nonce));

    uint8_t keyNonce[KEY_NONCE_LEN] = {0};
    fillRandomBytes(keyNonce, sizeof(keyNonce), stubWordSeq);
    const uint8_t want12[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0A, 0x0B, 0x0C};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want12, keyNonce, sizeof(keyNonce));
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

// --- ChaCha20-Poly1305 (RFC 8439 vectors, external to this code) ---------------

void test_chacha20_block_matches_rfc8439_section_2_3_2(void) {
    // Key 00..1f, nonce 00000009:0000004a:00000000, counter 1.
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    const uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
                               0x00, 0x00, 0x00, 0x00};
    uint8_t out[64];
    chacha20Block(key, 1, nonce, out);
    TEST_ASSERT_EQUAL_STRING("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                             "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
                             toHex(out, sizeof(out)).c_str());
}

void test_chacha20_encrypt_matches_rfc8439_section_2_4_2(void) {
    // Key 00..1f, nonce 00000000:0000004a:00000000, counter 1, "Sunscreen" pt.
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    const uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
                               0x00, 0x00, 0x00, 0x00};
    static const char kPt[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
        "future, sunscreen would be it.";
    const size_t ptLen = sizeof(kPt) - 1;
    uint8_t ct[128] = {0};
    uint8_t tag[16];
    chacha20Poly1305Encrypt(key, nonce, nullptr, 0,
                            reinterpret_cast<const uint8_t*>(kPt), ptLen, ct, tag);
    // Ciphertext prefix per RFC 8439 §2.4.2 (6e2e359a…).
    TEST_ASSERT_EQUAL_STRING("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                             "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8",
                             toHex(ct, 64).c_str());
    // Decrypt round-trips.
    uint8_t back[128] = {0};
    TEST_ASSERT_TRUE(chacha20Poly1305Decrypt(key, nonce, nullptr, 0, ct, ptLen, tag, back));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kPt, back, ptLen);
}

void test_aead_short_message_with_aad_round_trip(void) {
    // Short (sub-block) message + short AAD: padding paths on both sides.
    // Poly1305 itself is pinned transitively by the §2.8.2 tag below.
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0xC0 + i);
    const uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    static const uint8_t kAad[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01};
    static const char kMsg[] = "Cryptographic Forum Research Group";
    uint8_t ct[64] = {0};
    uint8_t tag[16];
    chacha20Poly1305Encrypt(key, nonce, kAad, sizeof(kAad),
                            reinterpret_cast<const uint8_t*>(kMsg), sizeof(kMsg) - 1, ct, tag);
    uint8_t back[64] = {0};
    TEST_ASSERT_TRUE(chacha20Poly1305Decrypt(key, nonce, kAad, sizeof(kAad), ct,
                                             sizeof(kMsg) - 1, tag, back));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kMsg, back, sizeof(kMsg) - 1);
    // Ciphertext differs from plaintext (actually encrypted).
    TEST_ASSERT_FALSE(memcmp(ct, kMsg, sizeof(kMsg) - 1) == 0);
}

void test_aead_matches_rfc8439_section_2_8_2(void) {
    // Key 8081…9f, nonce 07000000:40414243:44454647, AAD 50515253c0…c7,
    // "Sunscreen" plaintext → ct d31a8d34…6116, tag 1ae10b59….
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
    const uint8_t nonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
                               0x44, 0x45, 0x46, 0x47};
    const uint8_t aad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
                             0xc4, 0xc5, 0xc6, 0xc7};
    static const char kPt[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
        "future, sunscreen would be it.";
    const size_t ptLen = sizeof(kPt) - 1;
    uint8_t ct[128] = {0};
    uint8_t tag[16];
    chacha20Poly1305Encrypt(key, nonce, aad, sizeof(aad),
                            reinterpret_cast<const uint8_t*>(kPt), ptLen, ct, tag);
    TEST_ASSERT_EQUAL_STRING("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                             "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                             "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                             "3ff4def08e4b7a9de576d26586cec64b6116",
                             toHex(ct, ptLen).c_str());
    TEST_ASSERT_EQUAL_STRING("1ae10b594f09e26a7e902ecbd0600691", toHex(tag, 16).c_str());
    // Decrypt accepts; flipped tag rejects and zeroes the plaintext buffer.
    uint8_t back[128];
    memset(back, 0xAA, sizeof(back));
    TEST_ASSERT_TRUE(chacha20Poly1305Decrypt(key, nonce, aad, sizeof(aad), ct, ptLen, tag, back));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kPt, back, ptLen);
    uint8_t badTag[16];
    memcpy(badTag, tag, 16);
    badTag[0] ^= 0x01;
    memset(back, 0xAA, sizeof(back));
    TEST_ASSERT_FALSE(chacha20Poly1305Decrypt(key, nonce, aad, sizeof(aad), ct, ptLen, badTag, back));
    static const uint8_t kZero[128] = {0};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kZero, back, ptLen);
    // Wrong AAD rejects too.
    uint8_t badAad[12];
    memcpy(badAad, aad, sizeof(aad));
    badAad[0] ^= 0x01;
    TEST_ASSERT_FALSE(chacha20Poly1305Decrypt(key, nonce, badAad, sizeof(aad), ct, ptLen, tag, back));
}

void test_aead_handles_empty_aad_and_plaintext(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t ct[1] = {0xAA};
    uint8_t tag[16];
    chacha20Poly1305Encrypt(key, nonce, nullptr, 0, nullptr, 0, ct, tag);
    uint8_t back[1] = {0xAA};
    TEST_ASSERT_TRUE(chacha20Poly1305Decrypt(key, nonce, nullptr, 0, nullptr, 0, tag, back));
}

void test_aead_null_args_never_crash(void) {
    // Never-crash contract for every null combination.
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t buf[64] = {0};
    uint8_t tag[16] = {0};
    chacha20Block(nullptr, 0, nonce, buf);
    chacha20Block(key, 0, nullptr, buf);
    chacha20Block(key, 0, nonce, nullptr);
    chacha20Poly1305Encrypt(nullptr, nonce, nullptr, 0, nullptr, 0, buf, tag);
    chacha20Poly1305Encrypt(key, nullptr, nullptr, 0, nullptr, 0, buf, tag);
    chacha20Poly1305Encrypt(key, nonce, nullptr, 0, nullptr, 0, nullptr, tag);
    chacha20Poly1305Encrypt(key, nonce, nullptr, 0, nullptr, 0, buf, nullptr);
    chacha20Poly1305Encrypt(key, nonce, buf, 4, nullptr, 4, buf, tag);  // len>0, null pt
    TEST_ASSERT_FALSE(chacha20Poly1305Decrypt(nullptr, nonce, nullptr, 0, buf, 16, tag, buf));
    TEST_ASSERT_FALSE(chacha20Poly1305Decrypt(key, nullptr, nullptr, 0, buf, 16, tag, buf));
    TEST_ASSERT_FALSE(chacha20Poly1305Decrypt(key, nonce, nullptr, 0, buf, 16, tag, nullptr));
    TEST_ASSERT_FALSE(chacha20Poly1305Decrypt(key, nonce, nullptr, 0, nullptr, 16, tag, buf));
    TEST_ASSERT_TRUE(toHex(nullptr, 8).empty());
    uint8_t out[8];
    TEST_ASSERT_EQUAL_size_t(0, unhex("0011", nullptr, sizeof(out)));
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
    RUN_TEST(test_key_wrap_rejects_malformed_inputs);
    RUN_TEST(test_key_unwrap_fails_closed_on_tamper);
    RUN_TEST(test_fill_random_bytes_is_little_endian_per_word);
    RUN_TEST(test_fill_random_bytes_spans_words_for_nonce_lengths);
    RUN_TEST(test_fill_random_bytes_handles_partial_tail_and_nulls);
    RUN_TEST(test_chacha20_block_matches_rfc8439_section_2_3_2);
    RUN_TEST(test_chacha20_encrypt_matches_rfc8439_section_2_4_2);
    RUN_TEST(test_aead_short_message_with_aad_round_trip);
    RUN_TEST(test_aead_matches_rfc8439_section_2_8_2);
    RUN_TEST(test_aead_handles_empty_aad_and_plaintext);
    RUN_TEST(test_aead_null_args_never_crash);
}

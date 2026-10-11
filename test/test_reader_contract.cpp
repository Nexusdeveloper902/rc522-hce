/**
 * test_reader_contract.cpp — NfcReader interface + end-to-end tap simulation.
 *
 * Proves the reusable contract without hardware: the mock behaves like one
 * tap per push, HceProof has the documented empty/present/key semantics,
 * and a full simulated HCE tap (build CHALLENGE -> phone MAC via HMAC ->
 * parse -> verify) identifies the same credential the phone claims.
 * Any app built on NfcReader relies on exactly these behaviors.
 */
#include <unity.h>

#include <cstring>
#include <string>

#include "HceProtocol.h"
#include "MockNfcReader.h"
#include "NfcReader.h"

using namespace rc522hce;

// --- Mock contract ----------------------------------------------------------------

void test_mock_begin_always_succeeds(void) {
    MockNfcReader r;
    TEST_ASSERT_TRUE(r.begin());
}

void test_mock_poll_is_false_when_idle(void) {
    MockNfcReader r;
    std::string id;
    TEST_ASSERT_FALSE(r.poll(id));
}

void test_mock_delivers_exactly_one_tap_per_push(void) {
    MockNfcReader r;
    r.pushTap("04A3B2C1");
    std::string id;
    TEST_ASSERT_TRUE(r.poll(id));
    TEST_ASSERT_EQUAL_STRING("04A3B2C1", id.c_str());
    TEST_ASSERT_FALSE(r.poll(id));  // consumed — no repeat
}

void test_mock_ignores_empty_pushes(void) {
    MockNfcReader r;
    r.pushTap("");
    std::string id;
    TEST_ASSERT_FALSE(r.poll(id));
}

void test_mock_newest_push_wins(void) {
    MockNfcReader r;
    r.pushTap("FIRST");
    r.pushTap("SECOND");
    std::string id;
    TEST_ASSERT_TRUE(r.poll(id));
    TEST_ASSERT_EQUAL_STRING("SECOND", id.c_str());
    TEST_ASSERT_FALSE(r.poll(id));
}

void test_mock_accepts_hce_credential_ids_verbatim(void) {
    MockNfcReader r;
    r.pushTap("PLS-K3Y7V3CT0R5Z");
    std::string id;
    TEST_ASSERT_TRUE(r.poll(id));
    TEST_ASSERT_EQUAL_STRING("PLS-K3Y7V3CT0R5Z", id.c_str());
}

void test_mock_label_is_nonempty(void) {
    MockNfcReader r;
    TEST_ASSERT_NOT_NULL(r.label());
    TEST_ASSERT_TRUE(r.label()[0] != '\0');
}

void test_mock_default_kind_is_physical_and_proof_empty(void) {
    MockNfcReader r;
    TEST_ASSERT_TRUE(r.kind() == CredentialKind::Physical);
    TEST_ASSERT_EQUAL_STRING("physical", r.lastKind());
    TEST_ASSERT_EQUAL_STRING("physical", credentialKindName(r.kind()));
    TEST_ASSERT_FALSE(r.lastProof().present());
    // setEnrollment is a safe no-op on the mock (only the radio driver uses it).
    r.setEnrollment(true, "secret");
    r.setEnrollment(false, "");
}

void test_transport_failure_leaves_stale_kind_and_proof(void) {
    // Contract: after poll() == false, kind()/lastProof() are stale (last
    // success) and must not be used. The mock has never succeeded, so it
    // stays at the Physical/empty default.
    MockNfcReader r;
    std::string id;
    TEST_ASSERT_FALSE(r.poll(id));
    TEST_ASSERT_TRUE(r.kind() == CredentialKind::Physical);
    TEST_ASSERT_FALSE(r.lastProof().present());
}

// --- HceProof semantics ---------------------------------------------------------------

void test_proof_empty_by_default(void) {
    HceProof p;
    TEST_ASSERT_FALSE(p.present());
    TEST_ASSERT_FALSE(p.hasKey());
}

void test_proof_present_needs_nonce_and_mac(void) {
    HceProof p;
    p.nonceHex = "0123456789abcdef";
    TEST_ASSERT_FALSE(p.present());  // mac missing
    p.macHex = std::string(64, 'a');
    TEST_ASSERT_TRUE(p.present());
}

void test_proof_key_needs_wrapped_and_nonce(void) {
    HceProof p;
    p.nonceHex = "0123456789abcdef";
    p.macHex = std::string(64, 'a');
    TEST_ASSERT_FALSE(p.hasKey());
    p.keyWrappedHex = std::string(64, 'b');
    TEST_ASSERT_FALSE(p.hasKey());  // key nonce missing
    p.keyNonceHex = std::string(32, 'c');
    TEST_ASSERT_TRUE(p.hasKey());
    p.clear();
    TEST_ASSERT_FALSE(p.present());
    TEST_ASSERT_FALSE(p.hasKey());
}

// --- Full simulated HCE tap (no hardware) ------------------------------------------------
// Reader builds CHALLENGE with nonce N; phone answers len + credId +
// HMAC(K, credId || N) + 9000; reader parses; server recomputes and compares.

void test_simulated_hce_tap_identifies_end_to_end(void) {
    uint8_t phoneKey[32];
    for (int i = 0; i < 32; i++) {
        phoneKey[i] = (uint8_t)(0x40 + i);
    }
    const std::string credId = "TEST-ANDROID-001";
    const uint8_t nonce[NONCE_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                      0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

    // Reader side: build the CHALLENGE APDU.
    uint8_t chal[32];
    TEST_ASSERT_EQUAL_size_t(5 + NONCE_LEN, buildChallenge(nonce, chal, sizeof(chal)));

    // Phone side: answer with len + credId + MAC + 9000.
    uint8_t mac[HMAC_LEN];
    uint8_t msg[64];
    memcpy(msg, credId.data(), credId.size());
    memcpy(msg + credId.size(), nonce, NONCE_LEN);
    hmacSha256(phoneKey, 32, msg, credId.size() + NONCE_LEN, mac);

    uint8_t answer[1 + 32 + 32 + 2];
    answer[0] = (uint8_t)credId.size();
    memcpy(answer + 1, credId.data(), credId.size());
    memcpy(answer + 1 + credId.size(), mac, HMAC_LEN);
    answer[1 + credId.size() + HMAC_LEN] = 0x90;
    answer[1 + credId.size() + HMAC_LEN + 1] = 0x00;
    const size_t answerLen = 1 + credId.size() + HMAC_LEN + 2;

    // Reader side: parse the answer.
    ChallengeResponse parsed;
    TEST_ASSERT_TRUE(parseChallengeResponse(answer, answerLen, parsed));
    TEST_ASSERT_TRUE(parsed.ok);
    TEST_ASSERT_EQUAL_STRING(credId.c_str(), parsed.credId.c_str());

    // Server side: recompute the MAC over (credId || nonce) and compare.
    uint8_t expected[HMAC_LEN];
    hmacSha256(phoneKey, 32, msg, credId.size() + NONCE_LEN, expected);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, parsed.mac, HMAC_LEN);

    // And the relay proof the reader would POST is the nonce + MAC hex.
    HceProof proof;
    proof.nonceHex = toHex(nonce, NONCE_LEN);
    proof.macHex = toHex(parsed.mac, HMAC_LEN);
    TEST_ASSERT_TRUE(proof.present());
    TEST_ASSERT_EQUAL_STRING("112233445566778899aabbccddeeff00", proof.nonceHex.c_str());
    TEST_ASSERT_FALSE(proof.hasKey());  // operation tap carries no key
}

void test_simulated_tap_with_wrong_key_fails_verification(void) {
    // Same transcript, different server-side key => MAC mismatch => the
    // server must refuse (403). The reader relay itself is unchanged.
    uint8_t phoneKey[32], otherKey[32];
    memset(phoneKey, 0x41, 32);
    memset(otherKey, 0x42, 32);
    const std::string credId = "CRED-X";
    const uint8_t nonce[NONCE_LEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    uint8_t msg[64];
    memcpy(msg, credId.data(), credId.size());
    memcpy(msg + credId.size(), nonce, NONCE_LEN);
    uint8_t phoneMac[HMAC_LEN], serverMac[HMAC_LEN];
    hmacSha256(phoneKey, 32, msg, credId.size() + NONCE_LEN, phoneMac);
    hmacSha256(otherKey, 32, msg, credId.size() + NONCE_LEN, serverMac);
    TEST_ASSERT_FALSE(memcmp(phoneMac, serverMac, HMAC_LEN) == 0);
}

void test_simulated_enrollment_wraps_and_unwraps(void) {
    // Pairing tap: after CHALLENGE the reader sends ENROLL, the phone hands
    // over K_cred once, the reader wraps it — and the server unwraps it to
    // the same key it just verified the CHALLENGE proof under.
    uint8_t phoneKey[32];
    for (int i = 0; i < 32; i++) {
        phoneKey[i] = (uint8_t)i;
    }
    uint8_t enrollResp[34];
    memcpy(enrollResp, phoneKey, 32);
    enrollResp[32] = 0x90;
    enrollResp[33] = 0x00;

    uint8_t collected[32];
    TEST_ASSERT_TRUE(parseEnrollResponse(enrollResp, sizeof(enrollResp), collected));

    const std::string wrapped =
        wrapKeyHex("reader-secret", "CRED-E", "000102030405060708090a0b", collected);
    TEST_ASSERT_EQUAL_UINT32(120, (uint32_t)wrapped.size());  // 24 + 64 + 32

    // Server unwraps with the shared helper and checks it equals the key.
    uint8_t unwrapped[32];
    TEST_ASSERT_EQUAL_size_t(32, unwrapKeyHex("reader-secret", "CRED-E",
                                              "000102030405060708090a0b", wrapped, unwrapped));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(phoneKey, unwrapped, 32);
    memset(unwrapped, 0, sizeof(unwrapped));
}

void runReaderContractTests() {
    RUN_TEST(test_mock_begin_always_succeeds);
    RUN_TEST(test_mock_poll_is_false_when_idle);
    RUN_TEST(test_mock_delivers_exactly_one_tap_per_push);
    RUN_TEST(test_mock_ignores_empty_pushes);
    RUN_TEST(test_mock_newest_push_wins);
    RUN_TEST(test_mock_accepts_hce_credential_ids_verbatim);
    RUN_TEST(test_mock_label_is_nonempty);
    RUN_TEST(test_mock_default_kind_is_physical_and_proof_empty);
    RUN_TEST(test_transport_failure_leaves_stale_kind_and_proof);
    RUN_TEST(test_proof_empty_by_default);
    RUN_TEST(test_proof_present_needs_nonce_and_mac);
    RUN_TEST(test_proof_key_needs_wrapped_and_nonce);
    RUN_TEST(test_simulated_hce_tap_identifies_end_to_end);
    RUN_TEST(test_simulated_tap_with_wrong_key_fails_verification);
    RUN_TEST(test_simulated_enrollment_wraps_and_unwraps);
}

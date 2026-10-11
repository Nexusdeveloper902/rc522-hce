/**
 * test_hce_apdu.cpp — APDU builders/parsers: byte-exact wire contract.
 *
 * Every byte here is the interop contract between the phone app and the
 * reader. If any of these fail, phones stop identifying — that is why
 * builders are pinned byte-for-byte and parsers are pinned against both
 * success shapes and every documented failure shape.
 */
#include <unity.h>

#include <cstring>
#include <string>

#include "HceProtocol.h"

using namespace rc522hce;

// --- SELECT builder ----------------------------------------------------------

void test_select_builder_is_byte_exact(void) {
    uint8_t out[16];
    const size_t n = buildSelectAid(out, sizeof(out));

    const uint8_t want[] = {0x00, 0xA4, 0x04, 0x00, 0x07,
                            0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    TEST_ASSERT_EQUAL_size_t(sizeof(want), n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, out, sizeof(want));
}

void test_select_builder_refuses_short_buffer(void) {
    uint8_t out[11];  // one byte short of the 12-byte SELECT
    TEST_ASSERT_EQUAL_size_t(0, buildSelectAid(out, sizeof(out)));
}

void test_select_builder_rejects_null_and_empty(void) {
    uint8_t out[16];
    TEST_ASSERT_EQUAL_size_t(0, buildSelectAid(nullptr, sizeof(out)));
    TEST_ASSERT_EQUAL_size_t(0, buildSelectAid(out, 0));
    TEST_ASSERT_EQUAL_size_t(0, buildSelectAid(nullptr, 0));
}

void test_select_aid_constant_is_f_category(void) {
    // Proprietary 'F…' AID category: first nibble must be 0xF.
    TEST_ASSERT_EQUAL_size_t(7, AID_LEN);
    TEST_ASSERT_EQUAL_UINT8(0xF0, AID[0]);
}

// --- CHALLENGE builder --------------------------------------------------------

void test_challenge_builder_is_byte_exact(void) {
    const uint8_t nonce[NONCE_LEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t out[32];
    const size_t n = buildChallenge(nonce, out, sizeof(out));

    const uint8_t want[] = {0x80, 0x10, 0x00, 0x00, 0x10,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    TEST_ASSERT_EQUAL_size_t(sizeof(want), n);
    TEST_ASSERT_EQUAL_size_t(5 + NONCE_LEN, n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, out, sizeof(want));
}

void test_challenge_builder_embeds_any_nonce_verbatim(void) {
    // The fresh nonce lets the server detect replays; whatever NONCE_LEN
    // bytes go in must come out verbatim (replay rejection itself is
    // server-side).
    const uint8_t nonce[NONCE_LEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42, 0x13,
                                      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t out[32];
    TEST_ASSERT_EQUAL_size_t(5 + NONCE_LEN, buildChallenge(nonce, out, sizeof(out)));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(nonce, out + 5, NONCE_LEN);
}

void test_challenge_builder_rejects_short_null(void) {
    uint8_t out[32];
    const uint8_t nonce[NONCE_LEN] = {0};
    TEST_ASSERT_EQUAL_size_t(0, buildChallenge(nonce, out, 5 + NONCE_LEN - 1));
    TEST_ASSERT_EQUAL_size_t(0, buildChallenge(nullptr, out, sizeof(out)));
    TEST_ASSERT_EQUAL_size_t(0, buildChallenge(nonce, nullptr, sizeof(out)));
}

// --- SELECT parser ------------------------------------------------------------

void test_select_parser_accepts_hce_ok(void) {
    const uint8_t resp[] = {'H', 'C', 'E', '-', 'O', 'K', 0x90, 0x00};
    TEST_ASSERT_EQUAL_INT(static_cast<int>(SelectOutcome::Selected),
                          static_cast<int>(parseSelectResponse(resp, sizeof(resp))));
}

void test_select_parser_reports_unknown_aid(void) {
    const uint8_t resp[] = {0x6A, 0x82};
    TEST_ASSERT_EQUAL_INT(static_cast<int>(SelectOutcome::UnknownAid),
                          static_cast<int>(parseSelectResponse(resp, sizeof(resp))));
}

void test_select_parser_rejects_malformed(void) {
    // Truncated, wrong payload with 9000, 9000 alone, empty.
    const uint8_t truncated[] = {0x90};
    const uint8_t wrongPayload[] = {'N', 'O', 'P', 'E', '!', '!', 0x90, 0x00};
    const uint8_t bare9000[] = {0x90, 0x00};
    TEST_ASSERT_EQUAL_INT(static_cast<int>(SelectOutcome::Malformed),
                          static_cast<int>(parseSelectResponse(truncated, sizeof(truncated))));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(SelectOutcome::Malformed),
                          static_cast<int>(parseSelectResponse(wrongPayload, sizeof(wrongPayload))));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(SelectOutcome::Malformed),
                          static_cast<int>(parseSelectResponse(bare9000, sizeof(bare9000))));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(SelectOutcome::Malformed),
                          static_cast<int>(parseSelectResponse(nullptr, 0)));
}

void test_select_parser_distinguishes_routing_from_framing(void) {
    // 6A82 = the phone's OS answered "no app for this AID" (app/routing
    // problem). Anything else malformed = OUR framing/read fault. The
    // reader logs them differently; the parser must keep them distinct.
    const uint8_t unknownAid[] = {0x6A, 0x82};
    const uint8_t garbage[] = {0x01, 0x02, 0x03, 0x6F, 0x00};
    TEST_ASSERT_EQUAL_INT(static_cast<int>(SelectOutcome::UnknownAid),
                          static_cast<int>(parseSelectResponse(unknownAid, sizeof(unknownAid))));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(SelectOutcome::Malformed),
                          static_cast<int>(parseSelectResponse(garbage, sizeof(garbage))));
}

// --- Shared interop vector (pinned in phone app + server + reader) ------------
// Literal values computed OUTSIDE this code (Python hmac):
//   K = 00 01 .. 1f, credId = "PLS-K3Y7V3CT0R5Z", nonce = 00 01 .. 0f
static const char kVectorCred[] = "PLS-K3Y7V3CT0R5Z";
static const uint8_t kVectorNonce[NONCE_LEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const uint8_t kVectorResponse[] = {
    0x10, 'P', 'L', 'S', '-', 'K', '3', 'Y', '7', 'V', '3', 'C', 'T', '0', 'R', '5', 'Z',
    0x70, 0xf3, 0x2d, 0x7b, 0x45, 0x81, 0x39, 0xd8, 0xf5, 0xf5, 0x22, 0xa7, 0x31, 0x4c, 0x31, 0x20,
    0x5e, 0xca, 0x50, 0x61, 0x9a, 0x5d, 0x26, 0xdc, 0x46, 0x6d, 0x7d, 0x5b, 0x60, 0xaa, 0xb1, 0x54,
    0x90, 0x00};

static void vectorKey(uint8_t key[32]) {
    for (int i = 0; i < 32; i++) {
        key[i] = static_cast<uint8_t>(i);
    }
}

// --- CHALLENGE parser -----------------------------------------------------------

void test_challenge_parser_extracts_the_relay_proof(void) {
    ChallengeResponse parsed;
    TEST_ASSERT_TRUE(parseChallengeResponse(kVectorResponse, sizeof(kVectorResponse), parsed));
    TEST_ASSERT_TRUE(parsed.ok);
    TEST_ASSERT_EQUAL_size_t(51, sizeof(kVectorResponse));  // 1 + 16 + 32 + 2, per the spec
    TEST_ASSERT_EQUAL_STRING(kVectorCred, parsed.credId.c_str());
    // The relay proof is exactly what the server expects, hex-encoded.
    TEST_ASSERT_EQUAL_STRING("000102030405060708090a0b0c0d0e0f", toHex(kVectorNonce, NONCE_LEN).c_str());
    TEST_ASSERT_EQUAL_STRING("70f32d7b458139d8f5f522a7314c31205eca50619a5d26dc466d7d5b60aab154",
                             toHex(parsed.mac, 32).c_str());
}

void test_challenge_parser_rejects_malformed(void) {
    ChallengeResponse out;
    // Bad length prefix (claims 16, frame holds 4).
    const uint8_t badPrefix[] = {0x10, 'A', 'B', 'C', 'D', 0x90, 0x00};
    TEST_ASSERT_FALSE(parseChallengeResponse(badPrefix, sizeof(badPrefix), out));
    // Zero-length credential.
    const uint8_t zeroLen[1 + 32 + 2] = {0x00};
    TEST_ASSERT_FALSE(parseChallengeResponse(zeroLen, sizeof(zeroLen), out));
    // Truncated MAC.
    const uint8_t truncated[] = {0x04, 'A', 'B', 'C', 'D', 0x01, 0x02, 0x90, 0x00};
    TEST_ASSERT_FALSE(parseChallengeResponse(truncated, sizeof(truncated), out));
    // Wrong status word.
    uint8_t wrongSw[sizeof(kVectorResponse)];
    memcpy(wrongSw, kVectorResponse, sizeof(wrongSw));
    wrongSw[sizeof(wrongSw) - 2] = 0x6F;
    TEST_ASSERT_FALSE(parseChallengeResponse(wrongSw, sizeof(wrongSw), out));
    // One trailing byte too many / too few.
    TEST_ASSERT_FALSE(parseChallengeResponse(kVectorResponse, sizeof(kVectorResponse) - 1, out));
    // "No key" status word is not a credential.
    const uint8_t noKey[] = {0x6A, 0x88};
    TEST_ASSERT_FALSE(parseChallengeResponse(noKey, sizeof(noKey), out));
    TEST_ASSERT_TRUE(isKeyMissing(noKey, sizeof(noKey)));
    TEST_ASSERT_FALSE(isKeyMissing(kVectorResponse, sizeof(kVectorResponse)));
    TEST_ASSERT_FALSE(isKeyMissing(nullptr, 0));
}

void test_challenge_parser_enforces_credential_length_limits(void) {
    // Longest legal id (32 B) parses; 33 B is rejected; empty is rejected.
    uint8_t maxResp[1 + 32 + 32 + 2];
    maxResp[0] = 32;
    memset(maxResp + 1, 'A', 32);
    memset(maxResp + 33, 0x55, 32);
    maxResp[65] = 0x90;
    maxResp[66] = 0x00;
    ChallengeResponse out;
    TEST_ASSERT_TRUE(parseChallengeResponse(maxResp, sizeof(maxResp), out));
    TEST_ASSERT_EQUAL_size_t(32, out.credId.size());

    uint8_t tooLong[1 + 33 + 32 + 2];
    tooLong[0] = 33;
    memset(tooLong + 1, 'A', 33);
    memset(tooLong + 34, 0x55, 32);
    tooLong[66] = 0x90;
    tooLong[67] = 0x00;
    TEST_ASSERT_FALSE(parseChallengeResponse(tooLong, sizeof(tooLong), out));
}

void test_challenge_parser_never_touches_the_rf_uid(void) {
    // The parsers do not even TAKE an RF UID — identical APDU bytes always
    // yield the identical credential id no matter which random UID the
    // phone presented on the RF layer. Pinned so a refactor can never
    // smuggle the UID into the identity path (Android randomizes it).
    const uint8_t rfUidTap1[] = {0x08, 0x11, 0x22, 0x33};
    const uint8_t rfUidTap2[] = {0x08, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    (void)rfUidTap1;
    (void)rfUidTap2;

    ChallengeResponse first, second;
    TEST_ASSERT_TRUE(parseChallengeResponse(kVectorResponse, sizeof(kVectorResponse), first));
    TEST_ASSERT_TRUE(parseChallengeResponse(kVectorResponse, sizeof(kVectorResponse), second));
    TEST_ASSERT_EQUAL_STRING(first.credId.c_str(), second.credId.c_str());
    TEST_ASSERT_EQUAL_STRING(kVectorCred, first.credId.c_str());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first.mac, second.mac, 32);
}

// --- ENROLL ---------------------------------------------------------------------

void test_enroll_builder_is_byte_exact(void) {
    uint8_t out[8];  // ENROLL is unchanged in v2 (5 bytes, Le = 32)
    const uint8_t want[] = {0x80, 0x20, 0x00, 0x00, 0x20};
    TEST_ASSERT_EQUAL_size_t(sizeof(want), buildEnroll(out, sizeof(out)));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, out, sizeof(want));
    TEST_ASSERT_EQUAL_size_t(0, buildEnroll(out, 4));
    TEST_ASSERT_EQUAL_size_t(0, buildEnroll(nullptr, sizeof(out)));
}

void test_enroll_parser_accepts_only_key_plus_9000(void) {
    uint8_t resp[34];
    vectorKey(resp);
    resp[32] = 0x90;
    resp[33] = 0x00;
    uint8_t key[32];
    memset(key, 0xEE, sizeof(key));
    TEST_ASSERT_TRUE(parseEnrollResponse(resp, sizeof(resp), key));
    uint8_t want[32];
    vectorKey(want);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, key, 32);

    // Window closed (6985), truncated, wrong SW, oversize: all refused.
    const uint8_t closed[] = {0x69, 0x85};
    TEST_ASSERT_FALSE(parseEnrollResponse(closed, sizeof(closed), key));
    TEST_ASSERT_FALSE(parseEnrollResponse(resp, 33, key));
    resp[33] = 0x01;
    TEST_ASSERT_FALSE(parseEnrollResponse(resp, sizeof(resp), key));
    uint8_t big[35] = {0};
    big[33] = 0x90;
    big[34] = 0x00;
    TEST_ASSERT_FALSE(parseEnrollResponse(big, sizeof(big), key));
    TEST_ASSERT_FALSE(parseEnrollResponse(nullptr, 34, key));
}

void test_is_ok_edge_cases(void) {
    const uint8_t ok[] = {0x01, 0x90, 0x00};
    const uint8_t bad[] = {0x01, 0x6F, 0x00};
    const uint8_t one[] = {0x90};
    TEST_ASSERT_TRUE(isOk(ok, sizeof(ok)));
    TEST_ASSERT_FALSE(isOk(bad, sizeof(bad)));
    TEST_ASSERT_FALSE(isOk(one, sizeof(one)));
    TEST_ASSERT_FALSE(isOk(nullptr, 3));
    TEST_ASSERT_FALSE(isOk(ok, 0));
}

void runHceApduTests() {
    RUN_TEST(test_select_builder_is_byte_exact);
    RUN_TEST(test_select_builder_refuses_short_buffer);
    RUN_TEST(test_select_builder_rejects_null_and_empty);
    RUN_TEST(test_select_aid_constant_is_f_category);
    RUN_TEST(test_challenge_builder_is_byte_exact);
    RUN_TEST(test_challenge_builder_embeds_any_nonce_verbatim);
    RUN_TEST(test_challenge_builder_rejects_short_null);
    RUN_TEST(test_select_parser_accepts_hce_ok);
    RUN_TEST(test_select_parser_reports_unknown_aid);
    RUN_TEST(test_select_parser_rejects_malformed);
    RUN_TEST(test_select_parser_distinguishes_routing_from_framing);
    RUN_TEST(test_challenge_parser_extracts_the_relay_proof);
    RUN_TEST(test_challenge_parser_rejects_malformed);
    RUN_TEST(test_challenge_parser_enforces_credential_length_limits);
    RUN_TEST(test_challenge_parser_never_touches_the_rf_uid);
    RUN_TEST(test_enroll_builder_is_byte_exact);
    RUN_TEST(test_enroll_parser_accepts_only_key_plus_9000);
    RUN_TEST(test_is_ok_edge_cases);
}

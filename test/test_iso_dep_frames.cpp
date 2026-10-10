/**
 * test_iso_dep_frames.cpp — ISO-DEP framing predicates the driver depends on.
 *
 * These are the bench-hardened rules extracted from the Arduino driver's
 * salvage path into pure, host-testable functions. A regression here is a
 * regression in every phone tap: SAK misclassification sends phones down
 * the MIFARE path (random UID posted as identity), WTX mishandling drops
 * slow-but-healthy answers, and bad I-block stripping corrupts the APDU.
 */
#include <unity.h>

#include <stdint.h>

#include "HceProtocol.h"

using namespace rc522hce;

// --- SAK classification ---------------------------------------------------------

void test_sak_0x20_promises_iso_dep(void) {
    TEST_ASSERT_TRUE(sakPromisesIsoDep(0x20));  // the HCE phone
}

void test_sak_mifare_values_do_not_promise_iso_dep(void) {
    TEST_ASSERT_FALSE(sakPromisesIsoDep(0x08));  // MIFARE Classic 1K
    TEST_ASSERT_FALSE(sakPromisesIsoDep(0x18));  // MIFARE Classic 4K
    TEST_ASSERT_FALSE(sakPromisesIsoDep(0x00));  // no SAK bits
    TEST_ASSERT_FALSE(sakPromisesIsoDep(0x24));  // T=CL bit set BUT UID incomplete (bit 3 = 0x04)
    // Note 0x28 DOES promise ISO-DEP: 0x08 is not part of the driver's
    // ((sak & 0x24) == 0x20) test — only 0x20 set + 0x04 clear matter.
    TEST_ASSERT_TRUE(sakPromisesIsoDep(0x28));
}

void test_sak_bit_math_matches_driver_test(void) {
    // The driver's own test is ((sak & 0x24) == 0x20) — pin equivalence.
    for (int sak = 0; sak < 256; sak++) {
        const bool want = ((sak & 0x24) == 0x20);
        TEST_ASSERT_EQUAL(want, sakPromisesIsoDep((uint8_t)sak));
    }
}

// --- PCB classes ------------------------------------------------------------------

void test_pcb_classes_are_mutually_exclusive(void) {
    TEST_ASSERT_TRUE(isIBlock(0x0A));   // I-block, block 0, CID present
    TEST_ASSERT_TRUE(isIBlock(0x1B));   // I-block, block 1, CID+NAD
    TEST_ASSERT_TRUE(isIBlock(0x02));   // bare I-block
    TEST_ASSERT_FALSE(isIBlock(0xA0));  // R-block ACK
    TEST_ASSERT_FALSE(isIBlock(0xF2));  // S(WTX)

    TEST_ASSERT_TRUE(isRBlock(0xA0));
    TEST_ASSERT_FALSE(isRBlock(0x0A));

    TEST_ASSERT_TRUE(isWtxRequest(0xF2));  // S(WTX), WTXM=1, no CID
    TEST_ASSERT_TRUE(isWtxRequest(0xFA));  // S(WTX) with CID bit
    TEST_ASSERT_FALSE(isWtxRequest(0x0A));  // I-block is not WTX
    TEST_ASSERT_FALSE(isWtxRequest(0xA0));  // R-block is not WTX
    TEST_ASSERT_FALSE(isWtxRequest(0xE0));  // S(DESELECT): C0 set but 30 bits differ
}

void test_wtx_frame_needs_min_length(void) {
    const uint8_t wtx[] = {0xF2, 0x01, 0x2A, 0x3B};  // 4 B: too short
    TEST_ASSERT_FALSE(isWtxFrame(wtx, sizeof(wtx)));
    const uint8_t wtxOk[] = {0xF2, 0x01, 0x2A, 0x3B, 0x4C};  // 5 B
    TEST_ASSERT_TRUE(isWtxFrame(wtxOk, sizeof(wtxOk)));
    TEST_ASSERT_FALSE(isWtxFrame(nullptr, 5));
    const uint8_t iblock[] = {0x0A, 0x00, 0x11, 0x22, 0x33};
    TEST_ASSERT_FALSE(isWtxFrame(iblock, sizeof(iblock)));
}

// --- I-block stripping ---------------------------------------------------------------

void test_strip_bare_i_block(void) {
    // PCB + INF(2) + CRC(2), no CID/NAD.
    const uint8_t frame[] = {0x02, 0x90, 0x00, 0xAA, 0xBB};
    size_t off = 0, len = 0;
    TEST_ASSERT_TRUE(stripIBlock(frame, sizeof(frame), 64, off, len));
    TEST_ASSERT_EQUAL_size_t(1, off);
    TEST_ASSERT_EQUAL_size_t(2, len);
    TEST_ASSERT_EQUAL_UINT8(0x90, frame[off]);
    TEST_ASSERT_EQUAL_UINT8(0x00, frame[off + 1]);
}

void test_strip_i_block_with_cid(void) {
    // The bench's real salvaged SELECT answer shape:
    // PCB(0A: I-block + CID) + CID(00) + "HCE-OK" + 9000 + CRC(2).
    const uint8_t inf[] = {'H', 'C', 'E', '-', 'O', 'K', 0x90, 0x00};
    uint8_t frame[2 + 8 + 2];
    frame[0] = 0x0A;
    frame[1] = 0x00;
    for (int i = 0; i < 8; i++) {
        frame[2 + i] = inf[i];
    }
    frame[10] = 0xC8;
    frame[11] = 0xC0;  // placeholder CRC bytes (strip does not verify CRC)
    size_t off = 0, len = 0;
    TEST_ASSERT_TRUE(stripIBlock(frame, sizeof(frame), 64, off, len));
    TEST_ASSERT_EQUAL_size_t(2, off);
    TEST_ASSERT_EQUAL_size_t(8, len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(inf, frame + off, 8);
    // And the stripped INF is exactly what the SELECT parser accepts.
    TEST_ASSERT_EQUAL_INT(static_cast<int>(SelectOutcome::Selected),
                          static_cast<int>(parseSelectResponse(frame + off, len)));
}

void test_strip_i_block_with_cid_and_nad(void) {
    const uint8_t frame[] = {0x0E, 0x00, 0x01, 0x90, 0x00, 0xAA, 0xBB};
    size_t off = 0, len = 0;
    TEST_ASSERT_TRUE(stripIBlock(frame, sizeof(frame), 64, off, len));
    TEST_ASSERT_EQUAL_size_t(3, off);
    TEST_ASSERT_EQUAL_size_t(2, len);
}

void test_strip_rejects_non_i_blocks_and_runt_frames(void) {
    size_t off = 0, len = 0;
    const uint8_t rblock[] = {0xA0, 0x00, 0x11, 0x22, 0x33};
    TEST_ASSERT_FALSE(stripIBlock(rblock, sizeof(rblock), 64, off, len));
    const uint8_t wtx[] = {0xF2, 0x01, 0xAA, 0xBB, 0xCC};
    TEST_ASSERT_FALSE(stripIBlock(wtx, sizeof(wtx), 64, off, len));
    const uint8_t runt[] = {0x02, 0x90, 0x00, 0xAA};  // 4 B < min 5
    TEST_ASSERT_FALSE(stripIBlock(runt, sizeof(runt), 64, off, len));
    const uint8_t prologueOnly[] = {0x02, 0xAA, 0xBB};  // too short anyway
    TEST_ASSERT_FALSE(stripIBlock(prologueOnly, sizeof(prologueOnly), 64, off, len));
    TEST_ASSERT_FALSE(stripIBlock(nullptr, 8, 64, off, len));
}

void test_strip_rejects_oversize_inf(void) {
    // INF bigger than the caller's buffer mirrors STATUS_NO_ROOM.
    const uint8_t frame[] = {0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0xAA, 0xBB};
    size_t off = 0, len = 0;
    TEST_ASSERT_FALSE(stripIBlock(frame, sizeof(frame), 4, off, len));
    TEST_ASSERT_TRUE(stripIBlock(frame, sizeof(frame), 5, off, len));
}

// --- Block-number resync ----------------------------------------------------------------

void test_block_resync_is_the_opposite_of_what_the_phone_echoed(void) {
    // Phone answered with PCB bit0=0 (it got our block 0) => we send 1.
    TEST_ASSERT_TRUE(nextBlockNumber(0x0A));
    // Phone answered with PCB bit0=1 => we send 0.
    TEST_ASSERT_FALSE(nextBlockNumber(0x0B));
    // CID/NAD bits do not affect the resync.
    TEST_ASSERT_TRUE(nextBlockNumber(0x02));
    TEST_ASSERT_FALSE(nextBlockNumber(0x03));
}

void runIsoDepFrameTests() {
    RUN_TEST(test_sak_0x20_promises_iso_dep);
    RUN_TEST(test_sak_mifare_values_do_not_promise_iso_dep);
    RUN_TEST(test_sak_bit_math_matches_driver_test);
    RUN_TEST(test_pcb_classes_are_mutually_exclusive);
    RUN_TEST(test_wtx_frame_needs_min_length);
    RUN_TEST(test_strip_bare_i_block);
    RUN_TEST(test_strip_i_block_with_cid);
    RUN_TEST(test_strip_i_block_with_cid_and_nad);
    RUN_TEST(test_strip_rejects_non_i_blocks_and_runt_frames);
    RUN_TEST(test_strip_rejects_oversize_inf);
    RUN_TEST(test_block_resync_is_the_opposite_of_what_the_phone_echoed);
}

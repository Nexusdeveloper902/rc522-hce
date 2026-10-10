/**
 * test_debouncer.cpp — tap debounce: one event per physical tap.
 *
 * The RC522 re-reports a resting card every poll; without suppression one
 * tap becomes dozens of events. These tests pin the three rules (resting
 * => single event, different id => immediate, same-after-absence =>
 * cooldown) plus wrap-safety across the millis() 49.7-day rollover.
 */
#include <unity.h>

#include <stdint.h>
#include <string>

#include "CardDebouncer.h"

using namespace rc522hce;

void test_same_id_within_cooldown_is_ignored(void) {
    CardDebouncer d(2000);

    TEST_ASSERT_TRUE(d.shouldProcess("A1", 1000));
    TEST_ASSERT_FALSE(d.shouldProcess("A1", 1500));  // 500 ms later — same card
    TEST_ASSERT_FALSE(d.shouldProcess("A1", 2900));  // still inside 2000 ms
}

void test_same_id_after_cooldown_is_accepted(void) {
    CardDebouncer d(2000);

    TEST_ASSERT_TRUE(d.shouldProcess("A1", 1000));
    d.markAbsent();                                 // card removed from reader
    TEST_ASSERT_TRUE(d.shouldProcess("A1", 3100));  // 2100 ms later — deliberate re-tap
}

void test_same_id_without_absence_is_never_reaccepted(void) {
    // A card resting on the antenna is rejected FOREVER (even past the
    // cooldown) until it is physically removed.
    CardDebouncer d(2000);

    TEST_ASSERT_TRUE(d.shouldProcess("A1", 1000));
    TEST_ASSERT_FALSE(d.shouldProcess("A1", 10000));  // 9 s later, never absent
    TEST_ASSERT_FALSE(d.shouldProcess("A1", 60000));  // a minute later, still resting
}

void test_different_id_is_accepted_immediately(void) {
    CardDebouncer d(2000);

    TEST_ASSERT_TRUE(d.shouldProcess("A1", 1000));
    TEST_ASSERT_TRUE(d.shouldProcess("B2", 1200));  // different credential: no wait
}

void test_card_resting_on_antenna_yields_single_event(void) {
    // Simulates the RC522 re-reporting a resting card every ~100 ms.
    CardDebouncer d(2000);
    uint32_t t = 100000;
    int accepted = 0;

    for (int i = 0; i < 50; ++i) {  // 5 seconds of polling
        if (d.shouldProcess("A1", t)) {
            ++accepted;
        }
        t += 100;
    }

    TEST_ASSERT_EQUAL_INT32(1, accepted);
}

void test_hce_credential_ids_debounce_like_card_uids(void) {
    // HCE credential ids are longer strings but debounce identically:
    // a phone held to the antenna must not double-fire.
    CardDebouncer d(2000);
    TEST_ASSERT_TRUE(d.shouldProcess("PLS-K3Y7V3CT0R5Z", 5000));
    TEST_ASSERT_FALSE(d.shouldProcess("PLS-K3Y7V3CT0R5Z", 5100));
    d.markAbsent();
    TEST_ASSERT_FALSE(d.shouldProcess("PLS-K3Y7V3CT0R5Z", 6000));
    TEST_ASSERT_TRUE(d.shouldProcess("PLS-K3Y7V3CT0R5Z", 7100));
}

void test_debounce_window_is_measured_from_last_accept(void) {
    // An ignored re-read must NOT extend the cooldown.
    CardDebouncer d(2000);

    TEST_ASSERT_TRUE(d.shouldProcess("A1", 1000));
    d.markAbsent();
    TEST_ASSERT_FALSE(d.shouldProcess("A1", 2500));  // ignored — does not refresh
    TEST_ASSERT_TRUE(d.shouldProcess("A1", 3100));   // 2100 ms after the ACCEPT
}

void test_reset_forgets_last_tap(void) {
    CardDebouncer d(2000);

    TEST_ASSERT_TRUE(d.shouldProcess("A1", 1000));
    d.reset();
    TEST_ASSERT_TRUE(d.shouldProcess("A1", 1100));  // reset → immediate re-accept
}

void test_millis_wraparound_is_safe(void) {
    CardDebouncer d(2000);
    const uint32_t nearWrap = 4294966000u;  // ~36 s before the 49.7-day wrap

    TEST_ASSERT_TRUE(d.shouldProcess("A1", nearWrap));
    d.markAbsent();
    // 1500 ms later, across the uint32 wrap boundary:
    TEST_ASSERT_FALSE(d.shouldProcess("A1", nearWrap + 1500));
    // and past the cooldown, still after the wrap:
    TEST_ASSERT_TRUE(d.shouldProcess("A1", nearWrap + 2100));
}

void runDebouncerTests() {
    RUN_TEST(test_same_id_within_cooldown_is_ignored);
    RUN_TEST(test_same_id_after_cooldown_is_accepted);
    RUN_TEST(test_same_id_without_absence_is_never_reaccepted);
    RUN_TEST(test_different_id_is_accepted_immediately);
    RUN_TEST(test_card_resting_on_antenna_yields_single_event);
    RUN_TEST(test_hce_credential_ids_debounce_like_card_uids);
    RUN_TEST(test_debounce_window_is_measured_from_last_accept);
    RUN_TEST(test_reset_forgets_last_tap);
    RUN_TEST(test_millis_wraparound_is_safe);
}

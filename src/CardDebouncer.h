/**
 * CardDebouncer.h — re-read suppression, millis()-based, pure C++.
 *
 * Rules:
 *   - A card RESTING on the antenna (same id seen poll after poll, never
 *     absent) yields exactly ONE event — it is never re-accepted until it
 *     is removed. (poll() == false → the caller must invoke markAbsent().)
 *   - A DIFFERENT id is accepted immediately (the previous card must have
 *     left the reader anyway).
 *   - The SAME id re-presented after an ABSENCE is accepted only once the
 *     cooldown window has elapsed since the last accept (a deliberate
 *     human re-tap), and never before it.
 */
#pragma once

#include <stdint.h>
#include <string>

namespace rc522hce {

class CardDebouncer {
public:
    explicit CardDebouncer(uint32_t cooldownMs) : cooldownMs_(cooldownMs) {}

    /**
     * True when this (id, nowMs) pair must be processed as a real tap.
     * Call ONLY when the reader reports a credential present.
     */
    bool shouldProcess(const std::string& id, uint32_t nowMs) {
        if (id != lastId_) {
            // A different credential: accept (the previous one had to leave first).
            accept(id, nowMs);
            return true;
        }
        // Same credential as last time: only a deliberate re-tap counts.
        if (!sawAbsentSinceAccept_) {
            return false;  // resting on the antenna — never re-fire
        }
        if (elapsed(nowMs, lastAcceptedMs_) < cooldownMs_) {
            return false;  // too soon after the last accept
        }
        accept(id, nowMs);
        return true;
    }

    /** Call whenever the reader reports NO credential present. */
    void markAbsent() {
        sawAbsentSinceAccept_ = true;
    }

    /** Forget the last tap (e.g. on mode change). */
    void reset() {
        lastId_.clear();
        lastAcceptedMs_ = 0;
        sawAbsentSinceAccept_ = true;
    }

private:
    static uint32_t elapsed(uint32_t now, uint32_t then) {
        // millis() wraps ~every 49.7 days; unsigned arithmetic is wrap-safe.
        return now - then;
    }

    void accept(const std::string& id, uint32_t nowMs) {
        lastId_ = id;
        lastAcceptedMs_ = nowMs;
        sawAbsentSinceAccept_ = false;
    }

    uint32_t cooldownMs_;
    std::string lastId_;
    uint32_t lastAcceptedMs_ = 0;
    bool sawAbsentSinceAccept_ = true;
};

}  // namespace rc522hce

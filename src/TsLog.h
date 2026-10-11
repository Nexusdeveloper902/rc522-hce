/**
 * TsLog.h — a Print decorator that prefixes millis() at each line start.
 *
 * Bench tool: correlating RF events in time (how long between RATS and
 * SELECT? did that answer arrive before or after removal?). Wraps any
 * Print (Serial in production) and is the diagnostics sink the reader takes
 * in its constructor. Single-threaded loop() assumed.
 *
 * Device-only (Arduino Print) — no host test, by construction.
 *
 * Configuration is a build flag / source-free too: pass any Print, e.g.
 *   `TsLog tsLog(Serial);`  →  `[1234] [NFC] RC522 detected …`
 * or wrap your own stream (a wifi/UDP logger, a buffering sink, …).
 */
#pragma once

#include <Arduino.h>

#include <stdint.h>  // not <cstdint>: some toolchains ship no C++ stdlib

namespace rc522hce {

class TsLog : public Print {
public:
    explicit TsLog(Print& out) : out_(out), fresh_(true) {}

    size_t write(uint8_t c) override {
        if (fresh_) {
            fresh_ = false;
            out_.print('[');
            out_.print((unsigned long)millis());
            out_.print(F("] "));
        }
        const size_t n = out_.write(c);
        if (c == '\n') {
            fresh_ = true;
        }
        return n;
    }

private:
    Print& out_;
    bool fresh_;
};

}  // namespace rc522hce

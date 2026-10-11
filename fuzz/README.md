# Fuzzing the wire parsers

The parsers consume **untrusted phone bytes** off NFC, so unit tests
alone are not the bar — these libFuzzer targets hammer them with mutated
inputs under ASan. A crash (or ASan/UBSan report) fails the run.

## Targets

| Target | Entry point | Corpus seeds |
|---|---|---|
| `fuzz_challenge` | `parseChallengeResponse` | pinned vector response, truncations, `6A88`, zeros |
| `fuzz_enroll` | `parseEnrollResponse` | pinned key+`9000`, `6985`, short |
| `fuzz_unhex` | `unhex` | valid/odd/garbage hex |
| `fuzz_strip` | `stripIBlock` + `isWtxFrame` | I-block (±CID), WTX, R-block, short |
| `fuzz_verify` | `verifyProof` (bytes hex-encoded past the hex gate) | zeros, `ff` |
| `fuzz_aead` | `chacha20Poly1305Decrypt` (nonce\|\|ct\|\|tag) | zeros, structured vector |

## Run locally (needs clang with libFuzzer)

```sh
for t in challenge enroll unhex strip verify aead; do
  clang++ -std=c++11 -g -O1 -fsanitize=fuzzer,address -Isrc \
    -o /tmp/fuzz_$t fuzz/fuzz_$t.cpp src/HceProtocol.cpp
  /tmp/fuzz_$t fuzz/corpus/$t -max_total_time=60
done
```

CI (`fuzz` job) does exactly this, 60 s per target. New crashes land as
`crash-*` / `oom-*` / `timeout-*` files in the working directory — attach
the reproducer to the bug report, add a minimized seed to
`fuzz/corpus/<target>/`, and pin a regression unit test in `test/`.

Rules: harnesses must stay fast (no sleeps, no network), cap input sizes
(the AEAD target caps at 96 B — production shapes are 32 B), and never
`exit()` on purpose. `LLVMFuzzerTestOneInput` returning 0 with no crash
is a pass.

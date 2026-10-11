# Contributing to RC522-HCE

Thanks for helping. This library is a credential-authentication system,
not just a reader driver — the bar for protocol and crypto changes is
deliberately higher than for docs and examples.

## Ground rules

- `main` is always releasable. CI (`ci.yml`: native tests + ESP32/Mega
  cross-compiles + build-flag rewire) must be green; the `CI gate` check
  is required and history must stay linear (no merge commits — rebase).
- Never force-push `main`, never commit secrets, keys, or real
  credentials. Test vectors use synthetic values only.
- This is a **credential-authentication protocol**: read
  `docs/SECURITY.md` before touching nonces, key wrap/unwrap,
  `verifyProof`, RNG selection, or replay handling.

## Development setup

```sh
pip install platformio          # or: python3 -m venv .venv && .venv/bin/pip install platformio
pio test -e native              # 109 host-side Unity tests, no board needed
pio test -e native-san          # same suite under AddressSanitizer + UBSan
pio test -e native-cov          # same suite with coverage (gate: 90% lines on src/)
```

Build the examples exactly like a consumer does (library in `lib/`):

```sh
# ESP32
rm -rf /tmp/consumer && mkdir -p /tmp/consumer/src /tmp/consumer/lib
cp examples/BasicTap/BasicTap.ino /tmp/consumer/src/main.cpp
ln -s "$PWD" /tmp/consumer/lib/RC522-HCE
printf '[env:board]\nplatform = espressif32\nframework = arduino\nboard = esp32dev\nbuild_flags = -DMFRC522_SPICLOCK=1000000u\nlib_deps =\n    miguelbalboa/MFRC522@^1.4.11\n' > /tmp/consumer/platformio.ini
pio run -d /tmp/consumer -e board
```

## Commits

Conventional Commits, case-insensitive type (CI lints this):

```text
feat: add per-reader key-encryption service hook
fix: resync block number after salvaged WTX
docs: clarify replay table must be atomic
test: pin AEAD tamper rejection
ci: run cross-compiles on tags too
security: require approved RNG in production
```

Types: `feat fix docs test ci cd security chore refactor perf build style revert`.
Scope (`feat(radio): …`) and `!` breaking markers welcome.

## Pull requests

- Fill in the PR template (protocol impact + security considerations are
  mandatory sections, not optional).
- Keep PRs small and linear; rebase onto `main`, no merge commits.
- The code owner is auto-requested for review (see `.github/CODEOWNERS`).
- Beyond unit tests, CI also runs: sanitizers, libFuzzer targets
  (`fuzz/`, 60 s each — reproduce locally per `fuzz/README.md`),
  coverage gate, ESP32/Mega cross-compiles, HIL-suite compile check,
  reference-backend unittest, Arduino Lint, and zizmor. New wire-parser
  code needs a fuzz seed in `fuzz/corpus/<target>/` plus a regression
  unit test in `test/`.

## Releases (maintainer)

Releases are cut by the release job in CI, not by hand:

1. Add a `CHANGELOG.md` entry under a new `## [x.y.z] - YYYY-MM-DD`
   section (release notes come from there; missing section falls back to
   generated notes), and bump `version` in **both** `library.json` and
   `library.properties` (CI fails if they disagree).
2. Push to `main`. Green CI → tag `v<version>` + GitHub release appear
   automatically. Re-pushing the same version releases nothing.
3. Breaking wire/protocol changes need a major bump **and** a versioned
   migration: phone app + reader + backend + new pinned test vector
   move together (`docs/MIGRATION.md`). `PROTOCOL_VERSION` never changes
   silently.

## Publishing (maintainer, one-time + per release)

- Arduino Library Manager: request indexing once by opening a submission
  issue on [`arduino/library-registry`](https://github.com/arduino/library-registry)
  (see their FAQ); every release tag is then picked up automatically. Keep
  `arduino-lint` (CI) clean — especially `library.properties`,
  `keywords.txt`, and `examples/` layout.
- PlatformIO registry: automatic — the release job runs
  `pio pkg publish` after cutting the release (needs the
  `PLATFORMIO_AUTH_TOKEN` repo secret, already configured). Users then
  install via `geek02/RC522-HCE@^x.y.z`.

## Security issues

Do **not** open a public issue for vulnerabilities. See `SECURITY.md`.

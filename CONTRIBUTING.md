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
pio test -e native              # 106 host-side Unity tests, no board needed
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

## Releases (maintainer)

Releases are cut by the CD workflow, not by hand:

1. Bump `version` in **both** `library.json` and `library.properties`
   (CI fails if they disagree).
2. Push to `main`. Green CI → tag `v<version>` + GitHub release appear
   automatically. Re-pushing the same version releases nothing.
3. Breaking wire/protocol changes need a major bump **and** a versioned
   migration: phone app + reader + backend + new pinned test vector
   move together. `PROTOCOL_VERSION` never changes silently.

## Security issues

Do **not** open a public issue for vulnerabilities. See `SECURITY.md`.

---
name: Bug report
about: Something reads wrong, fails to build, or misbehaves on hardware
title: "fix: "
labels: bug
---

## What happened

<!-- What you did, what you expected, what you got instead. -->

## Setup

- Library version (or commit):
- Board + Arduino core:
- Phone (for HCE taps) / card type:
- `platformio.ini` env or build flags (if customized):

## Evidence

<!-- Serial log excerpt (redact keys/secrets), steps to reproduce.
For HCE failures include the SAK/ATS line and status words, per docs/API.md §15. -->

```
paste log here
```

## Checklist

- [ ] Ran `pio test -e native` (does the host suite pass?)
- [ ] Checked `docs/WIRING.md` (power, 1 MHz SPI, 2–3 cm placement)
- [ ] No real keys or secrets pasted above

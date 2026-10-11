# Reference backend (protocol v2)

Drop-in server side for [`docs/API.md` §11](../../docs/API.md) —
`hce_verify.py` implements operation-tap verification, v2 key unwrap,
and proof-of-possession enrollment with **zero dependencies**
(Python 3.8+ stdlib only: `hashlib`, `hmac`, `sqlite3`).

```sh
python3 -m unittest test_hce_backend.py -v   # 10 tests, shared vector + RFC 8439
```

## Use

```python
from hce_verify import verify_proof, NonceStore, enroll

keys = load_keys()          # credential_id -> 32-byte key (HSM/KMS)
nonces = NonceStore("nonces.db")

# 1. cryptographic validity (constant-time)
if not verify_proof(tap.credential_id, tap.nonce_hex, tap.mac_hex,
                    keys[tap.credential_id]):
    reject("bad-mac")
# 2. freshness, claimed atomically (UNIQUE constraint — replay => False)
if not nonces.claim(tap.credential_id, tap.nonce_hex):
    reject("replay")
# 3. authorize the requested operation
authorize(...)
```

Enrollment taps add the wrapped key (see `enroll()` — unwrap, then the
same tap's CHALLENGE proof under the candidate, then store/rotate).

## Notes for production ports

- The pure-Python ChaCha20-Poly1305 here is **reference-grade** (correct,
  pinned against RFC 8439 §2.8.2, but slow and not side-channel
  hardened). Port to a vetted library (`cryptography`, BoringSSL, …)
  and keep this suite green against it — the shared vector in
  `test_hce_backend.py` must match `src/HceProtocol.h TestVector`
  exactly.
- `verify_proof` returning `True` twice for the same transcript is
  correct behavior (validity ≠ freshness) — the `NonceStore` is what
  rejects replays. See `docs/SECURITY.md` §§1–3.
- `reader_secret` requirements are unchanged: high-entropy, per device,
  never logged (`docs/SECURITY.md` §5).

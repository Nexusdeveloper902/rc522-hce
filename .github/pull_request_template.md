## Summary

<!-- What changes, and why. Link any related issue. -->

## Protocol impact

<!-- Delete what does not apply. `PROTOCOL_VERSION` is frozen per major:
any change to wire bytes, MAC inputs, or enrollment semantics needs a
versioned migration (phone + reader + backend + new test vector). -->

- [ ] No wire/protocol change (docs, driver internals, tests only)
- [ ] Wire/protocol change — `PROTOCOL_VERSION` bumped, vector updated,
      phone app + backend migration noted

## Security considerations

<!-- Credential-authentication code: threat model in docs/SECURITY.md.
Does this touch nonces, key wrap/unwrap, verifyProof, RNG, or replay?
If yes, explain why the change preserves the contract. -->

- [ ] No security-relevant change, or reasoning below:

## Testing

<!-- Paste or tick what you ran. CI runs all of this anyway. -->

- [ ] `pio test -e native` (host unit tests)
- [ ] Example builds (`esp32dev`, `megaatmega2560`) — or CI did
- [ ] Hardware tap test (board + phone): <!-- board, result -->

## Checklist

- [ ] Title follows Conventional Commits (`feat:`, `fix:`, `docs:` …)
- [ ] `library.json` and `library.properties` versions still agree
      (bump both together **only** to cut a release — green CI on main
      releases automatically)
- [ ] Docs updated (`README.md` / `docs/`) if behavior changed
- [ ] No secrets, keys, or vectors with real credentials added

# Security Policy — lore-mark-verify-otp

This document is the threat model for the **Erlang/OTP cold-verifier** for
L43 Mirror-Mark v1 Re-Derivable-Receipts. It is repo-specific: every
statement below describes the code actually shipped in
`src/lore_mark_verify.erl`, not a generic template.

Read it before deploying this module in a regulator-, partner-, or
audit-facing process.

---

## 1. What this module is (and is not)

`lore_mark_verify` is a **pure, verify-only** library. Its job is to answer
one question with a closed-enum verdict:

> Given a `(payload, mark, key, corpus_sha)` tuple, was `mark` produced by
> HMAC-SHA256 over `0x01 || corpus_sha || payload` under `key`?

It is:

- **Pure** — every exported function is a deterministic function of its
  arguments. No network, no disk, no DB, no process state, no `ets`, no
  clock, no RNG. There is nothing to misconfigure at runtime.
- **Dependency-free at runtime** — `rebar.config` pins `{deps, []}` and the
  app descriptor declares only `kernel`, `stdlib`, `crypto`. There is **no
  transitive trust boundary**: a regulator can re-derive a verdict with a
  stock OTP install and nothing from the Limitless source tree. Adding any
  Hex dependency would defeat this property and is a firewall break
  (R145.B sibling-not-stacked).
- **Verify-first** — `sign/3` exists, but is documented and used as a
  **test-harness/round-trip helper only**. Production regulator workflow is
  verify-only. The signing side of the wire format lives in the sibling
  emit package `github.com/davly/limitless-beam-otp`.

It is **not**:

- A key-management system. It never generates, stores, derives, rotates, or
  transmits keys. The caller supplies `key` on every `verify/4` call.
- A transport. It does not move marks or payloads anywhere; the operator is
  responsible for getting `(payload, mark, key, corpus_sha)` to the process.
- A boundary-signing client. This module does not sign outbound requests and
  makes no claim to. (No Mirror-Mark is emitted by `verify/4`; the only
  signing primitive, `sign/3`, is test-only.)

---

## 2. Trust boundaries

```
   ┌─────────────────────────────────────────────────────────┐
   │  Caller process (regulator / partner-ops / audit job)    │
   │                                                          │
   │   holds: payload, mark, key, corpus_sha                  │
   │            │                                             │
   │            ▼                                             │
   │   lore_mark_verify:verify/4  ── pure, in-process ──►     │
   │            │                                             │
   │            ▼                                             │
   │   {ok, verified} | {error, <closed-enum reason>}         │
   └─────────────────────────────────────────────────────────┘
```

There is exactly **one** trust boundary that matters: the boundary between
the caller and the inputs it hands in.

- **`key`** is the sole secret. Whoever can call `verify/4` with the correct
  `key` can confirm a mark; whoever holds the `key` and `sign/3` can forge a
  mark. The security of the whole scheme reduces to the secrecy and
  integrity of `key`. This module deliberately holds no opinion on where
  `key` comes from — that is the caller's responsibility (see §5).
- **`corpus_sha`** is integrity-relevant, not secret. It binds a mark to a
  specific lore corpus. Supplying the wrong `corpus_sha` yields
  `err_corpus_mismatch` (a useful diagnostic — "you have the wrong
  `lore.tar.gz`"), not a silent pass.
- **`payload` / `mark`** are untrusted attacker-controlled inputs in the
  threat model: the whole point of verification is to decide whether a
  supplied mark is authentic. The module treats every byte of both as
  hostile (see §3).

Because the module is in-process and pure, it adds **no** new network
attack surface, no listening socket, no deserialization of complex
structures, and no privileged operation.

---

## 3. Attack surface and how it is handled

The only externally reachable surface is the four input binaries to
`verify/4` (and `verify/2`, `extract/1`). The verifier walks them
cheap-to-expensive and returns one of a **closed set** of reasons. The
ordering is load-bearing and matches the Go canonical:

| Step | Check                                   | On failure                      |
|------|-----------------------------------------|---------------------------------|
| 1    | `"lore@v1:"` prefix present             | `err_unknown_mark_version`      |
| 2    | encoded body is exactly 54 chars        | `err_malformed_mark`            |
| 3    | strict base64url-no-pad decode → 40 B   | `err_malformed_mark`            |
| 4    | corpus prefix matches (constant-time)   | `err_corpus_mismatch`           |
| 5    | HMAC re-derivation matches (const-time) | `err_signature_mismatch`        |

Specific hardening properties of the current code:

- **Strict base64url decode.** `base64url_decode_strict/1` first scans the
  input against the RFC 4648 §5 URL-safe alphabet (`A–Z a–z 0–9 - _`) and
  rejects any other byte — including `+`, `/`, and the padding `=`. A mark
  with trailing `=` padding is rejected as `err_malformed_mark`. This mirrors
  Go's `base64.RawURLEncoding` strict-reject behaviour and removes
  base64-malleability (alternative encodings of the same bytes) as a forgery
  avenue.
- **Length is checked before decode and after.** Step 2 rejects on encoded
  length 54; step 3 re-asserts the decoded body is exactly 40 bytes before
  any byte comparison. Short/long bodies cannot reach the HMAC path.
- **Constant-time comparison.** Both the corpus-prefix check (step 4) and the
  HMAC check (step 5) go through `constant_time_equal/2`, which uses
  `crypto:hash_equals/2` on OTP ≥ 25.1 and a bytewise XOR-fold fallback
  (`xor_fold_equal/3`) on older OTPs. The fallback touches every byte
  regardless of where the first mismatch occurs, so the verdict does not leak
  the position of the first differing byte through early return. See §4 for
  the residual timing caveat.
- **No exceptions on hostile input.** Structural rejections return
  `{error, ...}`; they do not raise. The only `error(badarg)` path is a
  **caller bug**: passing a `corpus_sha` whose length is not exactly 32
  bytes. That is a contract violation by the caller, not an attacker-reachable
  condition (the attacker controls `mark`/`payload`, not the locally supplied
  `corpus_sha`).
- **`extract/1` requires no key.** It surfaces the embedded 8-byte corpus
  prefix and 32-byte digest from a structurally valid mark *without*
  authenticating it. Treat `extract/1` output as **untrusted, structural
  metadata only** — it answers "which corpus does this mark claim?", never
  "is this mark authentic?". Authenticity is established solely by
  `verify/4` returning `{ok, verified}`.

---

## 4. Cryptographic assumptions and residual risks

- **Primitive.** Authenticity rests entirely on HMAC-SHA256
  (`crypto:mac(hmac, sha256, Key, ...)` from OTP `crypto`, i.e. the
  platform's OpenSSL/libcrypto). The module adds no custom cryptography; it
  composes the standard primitive with a fixed wire framing
  (`0x01 || corpus_sha || payload`).
- **8-byte corpus prefix is a diagnostic, not a security control.** Only 8
  bytes of `corpus_sha` are embedded in the mark. This is enough to give the
  operator a *useful early signal* that they hold the wrong corpus; it is
  **not** a second authentication factor. Forgery resistance comes entirely
  from the 32-byte HMAC, which is computed over the **full** 32-byte
  `corpus_sha`, not the 8-byte prefix. Do not treat a matching corpus prefix
  as evidence of anything beyond "probably the right corpus".
- **Truncation / length-extension.** HMAC is not vulnerable to the SHA-2
  length-extension attack, and the wire format pins a fixed 32-byte digest
  and fixed-length framing, so neither truncation nor extension of the digest
  is accepted (step 3 enforces exactly 40 decoded bytes).
- **Residual timing caveat (honest scope).** `constant_time_equal/2`
  guarantees constant-time **comparison of equal-length binaries** for the
  two security-relevant equality checks. It does **not** claim that the
  *entire* `verify/4` call is constant-time end-to-end: the early structural
  rejections (steps 1–3) short-circuit, and `crypto:mac/4`'s running time
  depends on payload length. An adversary who can submit chosen marks and
  measure response time can therefore distinguish *structural* failure
  classes and learn payload length — but cannot use the comparison step to
  recover the key or the expected digest byte-by-byte. If your deployment is
  in a remote-timing-sensitive setting, gate it behind a uniform-latency
  responder.
- **OTP version floor.** The strongest constant-time guarantee
  (`crypto:hash_equals/2`) requires **OTP ≥ 25.1**. On older OTPs the
  XOR-fold fallback is used; it is best-effort constant-time but, being
  pure-Erlang over `binary_to_list/1`, is more exposed to VM-level timing
  variation than the NIF. Prefer OTP ≥ 25.1 for any adversarial deployment.

---

## 5. Key handling guidance (caller responsibility)

This module never sees a key it did not receive as an argument, and never
persists one. The caller MUST:

- **Source the key from a secret store, never from source.** The signing key
  is the entire security boundary. The string in the test suite
  (`iik_dev_LORE_MARK_VERIFY_OTP_TEST_FIXTURE_NOT_FOR_PRODUCTION`) is a
  deliberately-named **dev fixture and not a production secret** — never use a
  hard-coded or example key in production.
- **Rotate keys out-of-band.** Rotation is a property of the *emit* side and
  the key store, not of this verifier. After rotation, marks signed under the
  old key will (correctly) return `err_signature_mismatch`; the verifier needs
  no change. Maintain the set of currently-valid keys at the caller.
- **Avoid logging inputs.** Do not log `key`. Logging `mark`/`corpus_sha`/
  `payload` may be acceptable for audit, but `mark` is sensitive in the sense
  that it is the authenticator — treat audit logs as needing the same
  protection as the data they attest.
- **Keep `corpus_sha` exactly 32 bytes.** Anything else is a caller bug and
  raises `badarg` (not a verdict).

---

## 6. The KAT-1 cohort firewall — change-control

The module embeds the R151 cohort anchor:

```
KAT-1 = HMAC-SHA256(key = <<>>, message = 0x01 || 32×0x00)   (33-byte message)
      = 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

This is independently reproducible with no Erlang toolchain (see the README
OpenSSL recipe). The `kat1/0` drift oracle re-derives it at runtime and
compares against the embedded literal; a `false` result means **this build
has silently drifted from the cohort canonical**.

**Security-relevant change rule:** editing the wire-format constants
(`?MARK_PREFIX`, `?MARK_VERSION_BYTE`, `?MARK_*_LEN`), the HMAC framing in
`sign_unchecked/3`/`verify_body/4`, or the `?KAT1_HEX` / `?KAT1_MARK`
literals is a **cohort firewall break**. Any such change MUST be made
simultaneously across **every** cohort sibling
(`lore-mark-verify` Go canonical, `-rs`, `-py`, `-ts`, this OTP package, and
`limitless-beam-otp`) and re-pinned with a fresh KAT, or the substrates will
silently disagree on what a valid mark is. Do not "fix" `kat1/0` in isolation
to make a test pass — a red drift oracle is reporting a real divergence.

---

## 7. Reporting a vulnerability

If you believe you have found a security issue in this module — for example,
an input that yields `{ok, verified}` for a mark not produced by the
canonical algorithm, a constant-time regression, or a cohort drift — please
report it privately rather than opening a public issue:

- Email: **david@vocala.co**
- Include: the exact `(payload, mark, key, corpus_sha)` reproducer (redact the
  real key; a synthetic key that reproduces is ideal), the OTP version, and
  the observed vs. expected verdict.

Please do not file forgery reproducers as public GitHub issues until a fix is
available.

---

## 8. Scope summary

| Property                         | This module |
|----------------------------------|-------------|
| Network surface                  | none (in-process, pure) |
| Runtime dependencies             | OTP `crypto` only; `{deps, []}` |
| Secrets held / persisted         | none — key passed per call |
| Signs outbound requests          | no (verify-only; `sign/3` is test-harness) |
| Constant-time digest compare     | yes (OTP ≥ 25.1 NIF; XOR-fold fallback below) |
| Whole-call constant-time         | no — structural failures short-circuit |
| Authenticity primitive           | HMAC-SHA256 over `0x01 ‖ corpus_sha ‖ payload` |
| Cross-substrate pin              | R151 KAT-1, OpenSSL-reproducible |

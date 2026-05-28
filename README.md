## lore-mark-verify (Erlang/OTP SDK)

Cohort-canonical regulator-grade cold-verifier for L43 Mirror-Mark v1
Re-Derivable-Receipts. Erlang/OTP SDK port.

- Algorithm-byte-identical to the Go canonical at
  [github.com/davly/lore-mark-verify](https://github.com/davly/lore-mark-verify)
- Pure OTP stdlib (`crypto`, `base64`, `binary`) -- zero Hex deps
- R151 KAT-1 anchor pinned: `239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca`
- OpenSSL-reproducible (no Erlang toolchain required for regulator)
- Compatible with OTP 25.1+ (older OTPs: manual XOR-fold fallback for
  constant-time equal)

### Build / test

    rebar3 compile
    rebar3 ct                # Common Test (37 cases)
    rebar3 as test proper    # PropEr (11 properties)
    rebar3 dialyzer

### Public API

```erlang
%% Full verify (key + corpus_sha explicit):
{ok, verified} = lore_mark_verify:verify(Payload, Mark, Key, CorpusSha).

%% Convenience verify against the implicit KAT-1 fixture
%% (Key = <<>>, CorpusSha = <<0:256>>):
{ok, verified} = lore_mark_verify:verify(Payload, Mark).

%% On failure, exactly one of:
{error, err_unknown_mark_version} | {error, err_malformed_mark}
    | {error, err_corpus_mismatch} | {error, err_signature_mismatch}.

%% Decode embedded corpus prefix + digest without the key:
{ok, MarkParts} = lore_mark_verify:extract(Mark).

%% Zero-input drift oracle:
{ReproducedHex, true} = lore_mark_verify:kat1().

%% Cohort-canonical constants (function-form so callers can match):
<<"lore@v1:">>           = lore_mark_verify:mark_prefix().
16#01                    = lore_mark_verify:mark_version().
8                        = lore_mark_verify:mark_corpus_prefix_len().
32                       = lore_mark_verify:sha256_digest_len().
40                       = lore_mark_verify:mark_body_len().
KAT1_HEX                 = lore_mark_verify:kat1_hex().
KAT1_MARK                = lore_mark_verify:kat1_mark().
```

### OpenSSL parity check (no Erlang required)

    printf '\x01' > /tmp/kat1.bin
    printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
    openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
    # -> 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca

### Composition with davly/limitless-beam-otp

This package is the COLD-VERIFY entry-point: a regulator/partner-ops
process holding `(payload, mark, key, corpus_sha)` calls `verify/4` and
receives a closed-enum verdict. The sibling
[github.com/davly/limitless-beam-otp](https://github.com/davly/limitless-beam-otp)
package ships the same wire format from the EMIT side
(`limitless_beam_mirror_mark:sign/2`). The two packages compose --
emitter signs with limitless-beam-otp, verifier re-derives with this
package, both produce byte-identical wire bytes for canonical inputs.

### Cohort siblings

Each commits byte-identical output for the same canonical inputs:

- `github.com/davly/lore-mark-verify` (Go canonical CLI)
- `github.com/davly/lore-mark-verify-rs` (Rust)
- `github.com/davly/lore-mark-verify-py` (Python)
- `github.com/davly/lore-mark-verify-ts` (TypeScript / npm)
- `github.com/davly/lore-mark-verify-otp` (this package)
- `github.com/davly/limitless-beam-otp` (BEAM in-process library)

### Wire format

```
mark = "lore@v1:" || base64url_no_pad(
           corpus_sha[:8]
           || HMAC-SHA256(key, 0x01 || corpus_sha || payload)
       )
```

Body = 8-byte corpus prefix + 32-byte HMAC = 40 bytes.
Base64url-no-padding-encoded body = 54 chars. Full mark = 62 chars.

### License

Apache-2.0 -- see [LICENSE](./LICENSE).

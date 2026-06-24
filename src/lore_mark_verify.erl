%%%-------------------------------------------------------------------
%%% @doc lore-mark-verify -- Erlang/OTP SDK port of the cohort-canonical
%%% regulator-grade cold-verifier for L43 Mirror-Mark v1
%%% Re-Derivable-Receipts.
%%%
%%% Algorithm-byte-identical to the Go canonical at
%%% github.com/davly/lore-mark-verify. Uses only OTP stdlib (`crypto`,
%%% `base64`, `binary`). Zero Hex deps -- adding any transitive dep
%%% would defeat the cohort property "no Limitless-source trust required
%%% at runtime".
%%%
%%% The cohort firewall pin is the R151 KAT-1 anchor:
%%%
%%%     HMAC-SHA256( key = &lt;&lt;&gt;&gt;, message = &lt;&lt;1,0,0,...,0&gt;&gt; (33 bytes) )
%%%     = 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
%%%
%%% Editing `kat1/0` without a paired bump of every cohort sibling
%%% (Go canonical / Rust foundry / Python / TS / limitless-cpp /
%%% limitless-dotnet / limitless-solidity) is a R151 firewall break.
%%%
%%% == Public API ==
%%%
%%% &lt;ul&gt;
%%%   &lt;li&gt;`verify(Bytes, Mark) -&gt; {ok, Verdict} | {error, Reason}`
%%%       -- Cold-verify a Mirror-Mark using the implicit KAT-1
%%%       fixture (corpus = 32x0x00, key = empty). Returns `{ok, verified}`
%%%       on round-trip success. Convenience entry for the cohort-canonical
%%%       KAT-1 self-test.&lt;/li&gt;
%%%   &lt;li&gt;`verify(Bytes, Mark, Key, CorpusSha) -&gt; {ok, Verdict} | {error, Reason}`
%%%       -- Full cold-verify with explicit `Key` (any-length binary) and
%%%       `CorpusSha` (32 bytes). Pure function -- no network, no DB.&lt;/li&gt;
%%%   &lt;li&gt;`extract(Mark) -&gt; {ok, MarkParts} | {error, Reason}`
%%%       -- Decode the embedded corpus-SHA prefix + HMAC digest WITHOUT
%%%       the key. Surfaces the 8-byte corpus prefix to the operator so
%%%       they can answer "do I have the right lore.tar.gz?" before
%%%       supplying the key.&lt;/li&gt;
%%%   &lt;li&gt;`kat1() -&gt; {ReproducedHex, Match}`
%%%       -- Zero-input drift oracle. Re-derives KAT-1 from canonical
%%%       inputs and compares against the embedded literal.&lt;/li&gt;
%%%   &lt;li&gt;`sign(Payload, Key, CorpusSha) -&gt; binary()`
%%%       -- Test-harness only; production code does NOT call this.&lt;/li&gt;
%%% &lt;/ul&gt;
%%%
%%% == Closed-enum verdicts (R115 cohort vocabulary) ==
%%%
%%% &lt;ul&gt;
%%%   &lt;li&gt;`{ok, verified}` -- round-trip success&lt;/li&gt;
%%%   &lt;li&gt;`{error, err_unknown_mark_version}` -- mark lacks "lore@v1:" prefix&lt;/li&gt;
%%%   &lt;li&gt;`{error, err_malformed_mark}` -- base64url decode failed /
%%%       body length wrong&lt;/li&gt;
%%%   &lt;li&gt;`{error, err_corpus_mismatch}` -- embedded corpus prefix !=
%%%       supplied corpus&lt;/li&gt;
%%%   &lt;li&gt;`{error, err_signature_mismatch}` -- HMAC re-derivation differs
%%%       (wrong key / tampered payload / forged mark)&lt;/li&gt;
%%% &lt;/ul&gt;
%%%
%%% Verification proceeds cheap-to-expensive (matches the Go canonical):
%%%
%%% &lt;ol&gt;
%%%   &lt;li&gt;Prefix check                            -&gt; `err_unknown_mark_version`&lt;/li&gt;
%%%   &lt;li&gt;Base64url decode                         -&gt; `err_malformed_mark`&lt;/li&gt;
%%%   &lt;li&gt;Body-length check                        -&gt; `err_malformed_mark`&lt;/li&gt;
%%%   &lt;li&gt;Corpus prefix comparison (constant-time) -&gt; `err_corpus_mismatch`&lt;/li&gt;
%%%   &lt;li&gt;HMAC re-derivation (constant-time)        -&gt; `err_signature_mismatch`&lt;/li&gt;
%%% &lt;/ol&gt;
%%%
%%% The corpus-prefix short-circuit at step 4 is load-bearing: a corpus
%%% drift gives the operator a useful diagnostic ("you have the wrong
%%% lore.tar.gz") instead of a generic HMAC failure.
%%%
%%% == Cohort siblings ==
%%%
%%% Each independently commits to byte-identical output for the same
%%% canonical inputs:
%%%
%%% &lt;ul&gt;
%%%   &lt;li&gt;`github.com/davly/lore-mark-verify`     (Go canonical CLI)&lt;/li&gt;
%%%   &lt;li&gt;`github.com/davly/lore-mark-verify-rs`  (Rust)&lt;/li&gt;
%%%   &lt;li&gt;`github.com/davly/lore-mark-verify-py`  (Python)&lt;/li&gt;
%%%   &lt;li&gt;`github.com/davly/lore-mark-verify-ts`  (TypeScript / npm)&lt;/li&gt;
%%%   &lt;li&gt;`github.com/davly/lore-mark-verify-otp` (this package)&lt;/li&gt;
%%%   &lt;li&gt;`github.com/davly/limitless-beam-otp`   (BEAM in-process library)&lt;/li&gt;
%%% &lt;/ul&gt;
%%%
%%% == Composition with davly/limitless-beam-otp ==
%%%
%%% This module is the COLD-VERIFY entry-point: a regulator/partner-ops
%%% binary holding (corpus_sha, payload, key, mark) calls `verify/4` and
%%% receives a closed-enum verdict. The sibling `limitless-beam-otp`
%%% package at github.com/davly/limitless-beam-otp ships the same
%%% wire format from the EMIT side (`limitless_beam_mirror_mark:sign/2`).
%%% The two packages compose: emitter signs with limitless-beam-otp,
%%% verifier re-derives with this package.
%%%
%%% == Wire format ==
%%%
%%% ```
%%% mark = "lore@v1:" || base64url_no_pad(
%%%            corpus_sha[:8]
%%%            || HMAC-SHA256(key, 0x01 || corpus_sha || payload)
%%%        )
%%% '''
%%%
%%% Body = 8-byte corpus prefix + 32-byte HMAC = 40 bytes.
%%% Base64url-no-padding-encoded = 54 chars (no padding).
%%% Full mark = 62 chars.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(lore_mark_verify).

%% Public API
-export([
    %% Verify
    verify/2,
    verify/4,
    %% Inspect (no key required)
    extract/1,
    %% Drift oracle
    kat1/0,
    %% Constants (function-form so callers can pattern-match)
    kat1_hex/0,
    kat1_mark/0,
    mark_prefix/0,
    mark_version/0,
    mark_body_len/0,
    mark_corpus_prefix_len/0,
    sha256_digest_len/0,
    %% Test-harness only
    sign/3
]).

-export_type([
    verify_verdict/0,
    verify_reason/0,
    verify_result/0,
    mark_parts/0
]).

-record(mark_parts, {
    version       :: binary(),
    corpus_prefix :: binary(),
    digest        :: binary()
}).

-type mark_parts() :: #mark_parts{}.

-type verify_verdict() :: verified.
-type verify_reason() ::
        err_unknown_mark_version
      | err_malformed_mark
      | err_corpus_mismatch
      | err_signature_mismatch.
-type verify_result() :: {ok, verify_verdict()} | {error, verify_reason()}.

%% ============================================================
%% Wire-format constants (R151 cohort cross-substrate pin)
%% ============================================================

-define(MARK_PREFIX, <<"lore@v1:">>).
-define(MARK_VERSION_BYTE, 16#01).
-define(MARK_CORPUS_PREFIX_LEN, 8).
-define(SHA256_DIGEST_LEN, 32).
-define(MARK_BODY_LEN, 40).             % corpus prefix (8) + digest (32)
-define(MARK_ENCODED_BODY_LEN, 54).     % base64url-no-pad(40 bytes)
-define(CORPUS_SHA_LEN, 32).

%% R151 KAT-1 cohort anchor -- byte-identical to every cohort sibling.
-define(KAT1_HEX,
    <<"239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca">>).
-define(KAT1_MARK,
    <<"lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg">>).

%% ============================================================
%% Public constants (function-form)
%% ============================================================

-spec kat1_hex() -> binary().
kat1_hex() -> ?KAT1_HEX.

-spec kat1_mark() -> binary().
kat1_mark() -> ?KAT1_MARK.

-spec mark_prefix() -> binary().
mark_prefix() -> ?MARK_PREFIX.

-spec mark_version() -> non_neg_integer().
mark_version() -> ?MARK_VERSION_BYTE.

-spec mark_body_len() -> pos_integer().
mark_body_len() -> ?MARK_BODY_LEN.

-spec mark_corpus_prefix_len() -> pos_integer().
mark_corpus_prefix_len() -> ?MARK_CORPUS_PREFIX_LEN.

-spec sha256_digest_len() -> pos_integer().
sha256_digest_len() -> ?SHA256_DIGEST_LEN.

%% ============================================================
%% Sign (test harness only)
%% ============================================================

%%--------------------------------------------------------------------
%% @doc Return the canonical Mirror-Mark for the given
%% (Payload, Key, CorpusSha) triple.
%%
%% Production code does NOT call this; the regulator-side workflow is
%% Verify-only. Exposed strictly for the test harness and round-trip
%% re-derivation.
%%
%% `CorpusSha` MUST be exactly 32 bytes; throws `badarg` otherwise.
%% @end
%%--------------------------------------------------------------------
-spec sign(Payload :: binary(), Key :: binary(), CorpusSha :: binary()) ->
        binary().
sign(Payload, Key, CorpusSha)
  when is_binary(Payload), is_binary(Key), is_binary(CorpusSha) ->
    case byte_size(CorpusSha) of
        ?CORPUS_SHA_LEN -> sign_unchecked(Payload, Key, CorpusSha);
        _ -> erlang:error(badarg, [Payload, Key, CorpusSha])
    end.

%% @private
sign_unchecked(Payload, Key, CorpusSha) ->
    HmacInput = <<?MARK_VERSION_BYTE, CorpusSha/binary, Payload/binary>>,
    Digest = crypto:mac(hmac, sha256, Key, HmacInput),
    <<CorpusPrefix:?MARK_CORPUS_PREFIX_LEN/binary, _Rest/binary>> = CorpusSha,
    Body = <<CorpusPrefix/binary, Digest/binary>>,
    Encoded = base64url_encode_no_pad(Body),
    <<(?MARK_PREFIX)/binary, Encoded/binary>>.

%% ============================================================
%% Verify
%% ============================================================

%%--------------------------------------------------------------------
%% @doc Convenience verify against the implicit KAT-1 fixture
%% (CorpusSha = &lt;&lt;0:256&gt;&gt;, Key = &lt;&lt;&gt;&gt;).
%%
%% Equivalent to `verify(Bytes, Mark, &lt;&lt;&gt;&gt;, &lt;&lt;0:256&gt;&gt;)`.
%%
%% Returns `{ok, verified}` on round-trip success; otherwise
%% `{error, Reason}` with `Reason` drawn from the closed-enum set.
%% @end
%%--------------------------------------------------------------------
-spec verify(Bytes :: binary(), Mark :: binary()) -> verify_result().
verify(Bytes, Mark) when is_binary(Bytes), is_binary(Mark) ->
    verify(Bytes, Mark, <<>>, <<0:256>>).

%%--------------------------------------------------------------------
%% @doc Full cold-verify of a Mirror-Mark string against
%% (Payload, Mark, Key, CorpusSha).
%%
%% Returns `{ok, verified}` on round-trip success; otherwise
%% `{error, Reason}` with `Reason` drawn from the closed-enum set:
%%
%% &lt;ul&gt;
%%   &lt;li&gt;`err_unknown_mark_version` -- mark lacks "lore@v1:" prefix&lt;/li&gt;
%%   &lt;li&gt;`err_malformed_mark` -- base64url decode failed / body length wrong&lt;/li&gt;
%%   &lt;li&gt;`err_corpus_mismatch` -- embedded corpus prefix != supplied corpus&lt;/li&gt;
%%   &lt;li&gt;`err_signature_mismatch` -- HMAC re-derivation differs&lt;/li&gt;
%% &lt;/ul&gt;
%%
%% `CorpusSha` MUST be exactly 32 bytes; throws `badarg` otherwise
%% (caller bug, not a closed-enum verdict).
%%
%% Cold-verify contract: pure function -- no network, no DB, no cohort
%% runtime dependencies.
%% @end
%%--------------------------------------------------------------------
-spec verify(Payload :: binary(), Mark :: binary(), Key :: binary(),
             CorpusSha :: binary()) -> verify_result().
verify(Payload, Mark, Key, CorpusSha)
  when is_binary(Payload), is_binary(Mark), is_binary(Key),
       is_binary(CorpusSha) ->
    case byte_size(CorpusSha) of
        ?CORPUS_SHA_LEN ->
            verify_with_prefix(Payload, Mark, Key, CorpusSha);
        _ ->
            erlang:error(badarg, [Payload, Mark, Key, CorpusSha])
    end.

%% @private
verify_with_prefix(Payload, Mark, Key, CorpusSha) ->
    Prefix = ?MARK_PREFIX,
    PrefixLen = byte_size(Prefix),
    case Mark of
        <<MarkPrefix:PrefixLen/binary, Encoded/binary>> when MarkPrefix =:= Prefix ->
            verify_encoded(Payload, Encoded, Key, CorpusSha);
        _ ->
            {error, err_unknown_mark_version}
    end.

%% @private
verify_encoded(Payload, Encoded, Key, CorpusSha) ->
    case byte_size(Encoded) of
        ?MARK_ENCODED_BODY_LEN ->
            case base64url_decode_strict(Encoded) of
                {ok, Body} when byte_size(Body) =:= ?MARK_BODY_LEN ->
                    verify_body(Payload, Body, Key, CorpusSha);
                _ ->
                    {error, err_malformed_mark}
            end;
        _ ->
            {error, err_malformed_mark}
    end.

%% @private
verify_body(Payload, Body, Key, CorpusSha) ->
    <<EmbeddedPrefix:?MARK_CORPUS_PREFIX_LEN/binary,
      EmbeddedDigest:?SHA256_DIGEST_LEN/binary>> = Body,
    <<ExpectedPrefix:?MARK_CORPUS_PREFIX_LEN/binary, _Rest/binary>> = CorpusSha,
    case constant_time_equal(EmbeddedPrefix, ExpectedPrefix) of
        false ->
            {error, err_corpus_mismatch};
        true ->
            HmacInput = <<?MARK_VERSION_BYTE, CorpusSha/binary, Payload/binary>>,
            Expected = crypto:mac(hmac, sha256, Key, HmacInput),
            case constant_time_equal(EmbeddedDigest, Expected) of
                true  -> {ok, verified};
                false -> {error, err_signature_mismatch}
            end
    end.

%% ============================================================
%% Extract -- structural decode (no key required)
%% ============================================================

%%--------------------------------------------------------------------
%% @doc Decode the embedded corpus-SHA prefix + HMAC digest from a
%% Mirror-Mark WITHOUT knowing the key.
%%
%% Returns `{ok, MarkParts}` on a structurally well-formed mark, where
%% `MarkParts` is an opaque record exposing `version` (binary),
%% `corpus_prefix` (8 bytes) and `digest` (32 bytes).
%%
%% Returns `{error, Reason}` with `Reason` drawn from:
%%
%% &lt;ul&gt;
%%   &lt;li&gt;`err_unknown_mark_version` -- mark lacks "lore@v1:" prefix&lt;/li&gt;
%%   &lt;li&gt;`err_malformed_mark` -- base64url decode failed / body length wrong&lt;/li&gt;
%% &lt;/ul&gt;
%%
%% Use the surfaced 8-byte corpus prefix to answer "do I have the
%% right lore.tar.gz?" before asking the operator for the key.
%% @end
%%--------------------------------------------------------------------
-spec extract(Mark :: binary()) ->
        {ok, mark_parts()} | {error, err_unknown_mark_version | err_malformed_mark}.
extract(Mark) when is_binary(Mark) ->
    Prefix = ?MARK_PREFIX,
    PrefixLen = byte_size(Prefix),
    case Mark of
        <<MarkPrefix:PrefixLen/binary, Encoded/binary>> when MarkPrefix =:= Prefix ->
            extract_encoded(Encoded);
        _ ->
            {error, err_unknown_mark_version}
    end.

%% @private
extract_encoded(Encoded) ->
    case byte_size(Encoded) of
        ?MARK_ENCODED_BODY_LEN ->
            case base64url_decode_strict(Encoded) of
                {ok, Body} when byte_size(Body) =:= ?MARK_BODY_LEN ->
                    <<CorpusPrefix:?MARK_CORPUS_PREFIX_LEN/binary,
                      Digest:?SHA256_DIGEST_LEN/binary>> = Body,
                    {ok, #mark_parts{
                        version = <<"v1">>,
                        corpus_prefix = CorpusPrefix,
                        digest = Digest
                    }};
                _ ->
                    {error, err_malformed_mark}
            end;
        _ ->
            {error, err_malformed_mark}
    end.

%% ============================================================
%% KAT-1 drift oracle
%% ============================================================

%%--------------------------------------------------------------------
%% @doc Re-derive the KAT-1 HMAC-SHA256 digest from canonical inputs
%% (key = empty, message = 0x01 || 32x0x00), hex-encode the 32-byte
%% output, and compare against the embedded literal `kat1_hex/0`.
%%
%% Returns `{ReproducedHex, Match}`.
%%
%% Structurally pure -- no inputs, no side effects. Exists so a
%% regulator (or automated drift-detection job) can answer the single
%% question "is this Erlang build itself correct?" in one line.
%%
%% If `Match` is `false`, this Erlang build has drifted from the cohort
%% canonical -- a R151 firewall break.
%% @end
%%--------------------------------------------------------------------
-spec kat1() -> {ReproducedHex :: binary(), Match :: boolean()}.
kat1() ->
    Input = <<?MARK_VERSION_BYTE, 0:256>>,
    Digest = crypto:mac(hmac, sha256, <<>>, Input),
    ReproducedHex = bin_to_hex_lower(Digest),
    Match = ReproducedHex =:= ?KAT1_HEX,
    {ReproducedHex, Match}.

%%====================================================================
%% Internal functions
%%====================================================================

%% @private
%% Constant-time equality. Erlang/OTP 25.1+ ships `crypto:hash_equals/2`;
%% older OTPs do not. Fallback uses a bytewise XOR fold so every byte
%% is touched regardless of mismatch position.
constant_time_equal(A, B) when byte_size(A) =:= byte_size(B) ->
    case erlang:function_exported(crypto, hash_equals, 2) of
        true  -> crypto:hash_equals(A, B);
        false -> xor_fold_equal(binary_to_list(A), binary_to_list(B), 0)
    end;
constant_time_equal(_, _) ->
    false.

%% @private
xor_fold_equal([], [], Acc) -> Acc =:= 0;
xor_fold_equal([X | Xs], [Y | Ys], Acc) ->
    xor_fold_equal(Xs, Ys, Acc bor (X bxor Y));
xor_fold_equal(_, _, _) ->
    false.

%% @private
%% RFC 4648 §5 base64url (URL-safe alphabet, no padding).
base64url_encode_no_pad(Bin) when is_binary(Bin) ->
    Std = base64:encode(Bin),
    %% Translate standard alphabet -> URL-safe and strip padding.
    Translated = binary:replace(
                    binary:replace(Std, <<"+">>, <<"-">>, [global]),
                    <<"/">>, <<"_">>, [global]),
    strip_trailing_equals(Translated).

%% @private
strip_trailing_equals(<<>>) -> <<>>;
strip_trailing_equals(Bin) ->
    case binary:last(Bin) of
        $= ->
            strip_trailing_equals(binary:part(Bin, 0, byte_size(Bin) - 1));
        _ ->
            Bin
    end.

%% @private
%% Strict base64url-no-padding decode. Returns `{ok, Bin}` on success
%% or `error` on any invalid character (`+`, `/`, `=`, anything outside
%% the RFC 4648 §5 URL-safe alphabet). Matches the Go base64.RawURLEncoding
%% strict-reject behaviour byte-for-byte.
base64url_decode_strict(Bin) when is_binary(Bin) ->
    case is_strict_base64url(Bin) of
        true ->
            try
                Restored = binary:replace(
                              binary:replace(Bin, <<"-">>, <<"+">>, [global]),
                              <<"_">>, <<"/">>, [global]),
                Padded = pad_to_multiple_of_4(Restored),
                {ok, base64:decode(Padded)}
            catch
                _:_ -> error
            end;
        false ->
            error
    end.

%% @private
is_strict_base64url(<<>>) -> true;
is_strict_base64url(<<C, Rest/binary>>) ->
    case is_url_safe_alphabet_char(C) of
        true  -> is_strict_base64url(Rest);
        false -> false
    end.

%% @private
%% RFC 4648 §5 URL-safe alphabet only: A-Z a-z 0-9 - _
is_url_safe_alphabet_char(C) when C >= $A, C =< $Z -> true;
is_url_safe_alphabet_char(C) when C >= $a, C =< $z -> true;
is_url_safe_alphabet_char(C) when C >= $0, C =< $9 -> true;
is_url_safe_alphabet_char($-) -> true;
is_url_safe_alphabet_char($_) -> true;
is_url_safe_alphabet_char(_) -> false.

%% @private
pad_to_multiple_of_4(Bin) ->
    case byte_size(Bin) rem 4 of
        0 -> Bin;
        1 -> <<Bin/binary, "===">>;
        2 -> <<Bin/binary, "==">>;
        3 -> <<Bin/binary, "=">>
    end.

%% @private
bin_to_hex_lower(Bin) when is_binary(Bin) ->
    iolist_to_binary([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).

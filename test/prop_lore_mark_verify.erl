%%%-------------------------------------------------------------------
%%% @doc PropEr properties for lore_mark_verify.
%%%
%%% Each property characterises a round-trip / closed-set invariant of
%%% the cohort-canonical Mirror-Mark v1 algorithm. The properties are
%%% deliberately small + cheap: PropEr's default numtests (100) runs
%%% fast even on a regulator CI box.
%%%
%%% Properties:
%%%
%%%  1. sign/verify round-trip is total over any (payload, key, corpus_sha)
%%%  2. KAT-1 inputs always produce KAT1_MARK (deterministic anchor)
%%%  3. Verify always rejects a flipped HMAC body (signature mismatch)
%%%  4. Verify always rejects a mark stripped of its prefix
%%%  5. Verify always rejects a mark whose v1 prefix is corrupted
%%%  6. extract is total over any well-formed mark
%%%  7. extract().corpus_prefix == corpus_sha[:8] for any valid sign output
%%%  8. extract().digest == HMAC re-derivation of canonical input
%%%  9. kat1() always matches (deterministic)
%%% 10. sign output length is always 62 bytes regardless of payload/key length
%%% 11. Verify rejects a different payload (signature mismatch)
%%%
%%% These run via `rebar3 proper` and gate the cohort firewall pin.
%%% @end
%%%-------------------------------------------------------------------
-module(prop_lore_mark_verify).

-include_lib("proper/include/proper.hrl").

%% ============================================================
%% Generators
%% ============================================================

corpus_sha() ->
    binary(32).

key() ->
    binary().                 % any-length binary, including empty

payload() ->
    binary().                 % any-length binary, including empty

%% ============================================================
%% Properties
%% ============================================================

prop_sign_verify_round_trip() ->
    ?FORALL({Payload, Key, Corpus}, {payload(), key(), corpus_sha()},
        begin
            Mark = lore_mark_verify:sign(Payload, Key, Corpus),
            {ok, verified} =:= lore_mark_verify:verify(Payload, Mark, Key, Corpus)
        end).

prop_kat1_inputs_produce_kat1_mark() ->
    ?FORALL(_Dummy, integer(),                  % dummy generator
        begin
            Mark = lore_mark_verify:sign(<<>>, <<>>, <<0:256>>),
            Mark =:= lore_mark_verify:kat1_mark()
        end).

prop_flipped_body_rejected_as_signature_mismatch() ->
    ?FORALL({Payload, Key, Corpus}, {payload(), key(), corpus_sha()},
        begin
            Mark = lore_mark_verify:sign(Payload, Key, Corpus),
            Prefix = lore_mark_verify:mark_prefix(),
            PrefixLen = byte_size(Prefix),
            <<P:PrefixLen/binary, Body/binary>> = Mark,
            %% Flip the LAST byte of the encoded body. The flip lands in
            %% the HMAC region (NOT the corpus prefix), so the verdict
            %% must be err_signature_mismatch OR err_malformed_mark
            %% (depending on whether the flip lands in the base64 alphabet
            %% boundary). The point is: a tampered mark is NEVER {ok,
            %% verified} and NEVER err_corpus_mismatch.
            BodyLen = byte_size(Body),
            <<BodyHead:(BodyLen - 1)/binary, Last>> = Body,
            FlippedLast = (Last bxor 16#01),
            Tampered = <<P/binary, BodyHead/binary, FlippedLast>>,
            case lore_mark_verify:verify(Payload, Tampered, Key, Corpus) of
                {ok, verified} -> false;
                {error, err_corpus_mismatch} -> false;
                {error, err_signature_mismatch} -> true;
                {error, err_malformed_mark} -> true;
                {error, err_unknown_mark_version} -> false
            end
        end).

prop_mark_without_prefix_rejected() ->
    ?FORALL({Payload, Key, Corpus}, {payload(), key(), corpus_sha()},
        begin
            Mark = lore_mark_verify:sign(Payload, Key, Corpus),
            Prefix = lore_mark_verify:mark_prefix(),
            PrefixLen = byte_size(Prefix),
            <<_P:PrefixLen/binary, Body/binary>> = Mark,
            %% Stripped: body alone (no "lore@v1:" prefix).
            Result = lore_mark_verify:verify(Payload, Body, Key, Corpus),
            Result =:= {error, err_unknown_mark_version}
        end).

prop_corrupted_v1_prefix_rejected() ->
    ?FORALL({Payload, Key, Corpus}, {payload(), key(), corpus_sha()},
        begin
            Mark = lore_mark_verify:sign(Payload, Key, Corpus),
            %% Replace "v1" with "v2" -- still nominally a mark but the
            %% v1-only verifier MUST reject.
            Corrupted = binary:replace(Mark, <<"lore@v1:">>, <<"lore@v2:">>),
            Result = lore_mark_verify:verify(Payload, Corrupted, Key, Corpus),
            Result =:= {error, err_unknown_mark_version}
        end).

prop_extract_total_over_valid_marks() ->
    ?FORALL({Payload, Key, Corpus}, {payload(), key(), corpus_sha()},
        begin
            Mark = lore_mark_verify:sign(Payload, Key, Corpus),
            case lore_mark_verify:extract(Mark) of
                {ok, _Parts} -> true;
                _            -> false
            end
        end).

prop_extract_corpus_prefix_matches_input() ->
    ?FORALL({Payload, Key, Corpus}, {payload(), key(), corpus_sha()},
        begin
            Mark = lore_mark_verify:sign(Payload, Key, Corpus),
            {ok, Parts} = lore_mark_verify:extract(Mark),
            {mark_parts, _Version, EmbeddedPrefix, _Digest} = Parts,
            <<Expected:8/binary, _Rest/binary>> = Corpus,
            EmbeddedPrefix =:= Expected
        end).

prop_extract_digest_matches_hmac_recomputation() ->
    ?FORALL({Payload, Key, Corpus}, {payload(), key(), corpus_sha()},
        begin
            Mark = lore_mark_verify:sign(Payload, Key, Corpus),
            {ok, Parts} = lore_mark_verify:extract(Mark),
            {mark_parts, _Version, _Prefix, Digest} = Parts,
            Input = <<16#01, Corpus/binary, Payload/binary>>,
            Expected = crypto:mac(hmac, sha256, Key, Input),
            Digest =:= Expected
        end).

prop_kat1_drift_oracle_always_matches() ->
    ?FORALL(_Dummy, integer(),
        begin
            {_Hex, Match} = lore_mark_verify:kat1(),
            Match =:= true
        end).

prop_sign_output_length_is_62_bytes() ->
    ?FORALL({Payload, Key, Corpus}, {payload(), key(), corpus_sha()},
        begin
            Mark = lore_mark_verify:sign(Payload, Key, Corpus),
            byte_size(Mark) =:= 62
        end).

prop_different_payload_rejected_as_signature_mismatch() ->
    ?FORALL({P1, P2, Key, Corpus}, {payload(), payload(), key(), corpus_sha()},
        ?IMPLIES(P1 =/= P2,
            begin
                Mark = lore_mark_verify:sign(P1, Key, Corpus),
                Result = lore_mark_verify:verify(P2, Mark, Key, Corpus),
                Result =:= {error, err_signature_mismatch}
            end)).

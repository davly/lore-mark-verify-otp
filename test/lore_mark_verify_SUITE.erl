%%%-------------------------------------------------------------------
%%% @doc Common Test suite for lore_mark_verify.
%%%
%%% Pins:
%%%   - Wire-form constants (prefix / version byte / lengths)
%%%   - R151 KAT-1 cohort firewall pin (hex + mark string)
%%%   - sign + verify round-trip
%%%   - All four R115 closed-enum verdicts (UnknownMarkVersion /
%%%     MalformedMark / CorpusMismatch / SignatureMismatch)
%%%   - extract() structural decoder
%%%   - kat1() drift oracle
%%%   - 2-arg verify/2 convenience (implicit KAT-1 fixture)
%%%
%%% Test discipline (R145.C FIREWALL-TEST-DISCIPLINE):
%%%   - Constants pinned to literal integers + byte sequences
%%%   - KAT-1 hex literal pinned byte-identically across cohort
%%%   - Round-trip verifies the EXACT digest pinned in lore_mark_verify
%%% @end
%%%-------------------------------------------------------------------
-module(lore_mark_verify_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    %% Wire-format constants
    prefix_literal/1,
    version_byte_literal/1,
    corpus_prefix_len_literal/1,
    digest_len_literal/1,
    body_len_literal/1,
    kat1_hex_literal/1,
    kat1_mark_literal/1,
    kat1_hex_is_64_chars/1,
    kat1_hex_is_lowercase/1,
    kat1_mark_is_62_chars/1,
    kat1_mark_starts_with_prefix/1,

    %% kat1/0 drift oracle
    kat1_returns_pair/1,
    kat1_reproduces_against_literal/1,
    kat1_reproduces_against_independent_hmac/1,

    %% sign + round-trip
    sign_returns_binary/1,
    sign_kat1_inputs_produce_kat1_mark/1,
    sign_round_trip_verifies/1,
    sign_bad_corpus_length_throws/1,

    %% verify/4
    verify_ok_round_trip/1,
    verify_no_prefix_returns_unknown_version/1,
    verify_v2_prefix_returns_unknown_version/1,
    verify_bad_base64_returns_malformed/1,
    verify_padding_rejected_returns_malformed/1,
    verify_short_body_returns_malformed/1,
    verify_long_body_returns_malformed/1,
    verify_wrong_corpus_returns_corpus_mismatch/1,
    verify_corpus_mismatch_before_signature_mismatch/1,
    verify_wrong_key_returns_signature_mismatch/1,
    verify_wrong_payload_returns_signature_mismatch/1,
    verify_bad_corpus_length_throws/1,

    %% verify/2 convenience
    verify2_kat1_round_trip/1,
    verify2_garbage_returns_unknown_version/1,

    %% extract/1
    extract_kat1_mark/1,
    extract_returns_mark_parts/1,
    extract_no_prefix_returns_unknown_version/1,
    extract_bad_base64_returns_malformed/1,
    extract_corpus_prefix_matches_input/1,

    %% OTP-28 prefix-pattern build-break regression (illegal-pattern guard)
    otp28_prefix_pattern_match_path/1
]).

%%--------------------------------------------------------------------
%% Suite plumbing
%%--------------------------------------------------------------------

suite() ->
    [{timetrap, {seconds, 30}}].

all() ->
    [
        prefix_literal,
        version_byte_literal,
        corpus_prefix_len_literal,
        digest_len_literal,
        body_len_literal,
        kat1_hex_literal,
        kat1_mark_literal,
        kat1_hex_is_64_chars,
        kat1_hex_is_lowercase,
        kat1_mark_is_62_chars,
        kat1_mark_starts_with_prefix,

        kat1_returns_pair,
        kat1_reproduces_against_literal,
        kat1_reproduces_against_independent_hmac,

        sign_returns_binary,
        sign_kat1_inputs_produce_kat1_mark,
        sign_round_trip_verifies,
        sign_bad_corpus_length_throws,

        verify_ok_round_trip,
        verify_no_prefix_returns_unknown_version,
        verify_v2_prefix_returns_unknown_version,
        verify_bad_base64_returns_malformed,
        verify_padding_rejected_returns_malformed,
        verify_short_body_returns_malformed,
        verify_long_body_returns_malformed,
        verify_wrong_corpus_returns_corpus_mismatch,
        verify_corpus_mismatch_before_signature_mismatch,
        verify_wrong_key_returns_signature_mismatch,
        verify_wrong_payload_returns_signature_mismatch,
        verify_bad_corpus_length_throws,

        verify2_kat1_round_trip,
        verify2_garbage_returns_unknown_version,

        extract_kat1_mark,
        extract_returns_mark_parts,
        extract_no_prefix_returns_unknown_version,
        extract_bad_base64_returns_malformed,
        extract_corpus_prefix_matches_input,

        otp28_prefix_pattern_match_path
    ].

init_per_suite(Config) ->
    %% Ensure crypto is loaded.
    {ok, _} = application:ensure_all_started(crypto),
    Config.

end_per_suite(_Config) ->
    ok.

%% Canonical dev fixture (NOT a production secret).
-define(DEV_KEY, <<"iik_dev_LORE_MARK_VERIFY_OTP_TEST_FIXTURE_NOT_FOR_PRODUCTION">>).
-define(DEV_PAYLOAD, <<"hello cohort world">>).

dev_corpus() ->
    crypto:hash(sha256, <<"dev-lore-corpus-fixture">>).

dev_mark() ->
    lore_mark_verify:sign(?DEV_PAYLOAD, ?DEV_KEY, dev_corpus()).

%%--------------------------------------------------------------------
%% Wire-format constants
%%--------------------------------------------------------------------

prefix_literal(_) ->
    <<"lore@v1:">> = lore_mark_verify:mark_prefix(),
    8 = byte_size(lore_mark_verify:mark_prefix()).

version_byte_literal(_) ->
    16#01 = lore_mark_verify:mark_version().

corpus_prefix_len_literal(_) ->
    8 = lore_mark_verify:mark_corpus_prefix_len().

digest_len_literal(_) ->
    32 = lore_mark_verify:sha256_digest_len().

body_len_literal(_) ->
    40 = lore_mark_verify:mark_body_len().

kat1_hex_literal(_) ->
    %% R151 cohort firewall pin -- byte-identical to every sibling.
    <<"239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca">> =
        lore_mark_verify:kat1_hex().

kat1_mark_literal(_) ->
    <<"lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg">> =
        lore_mark_verify:kat1_mark().

kat1_hex_is_64_chars(_) ->
    64 = byte_size(lore_mark_verify:kat1_hex()).

kat1_hex_is_lowercase(_) ->
    Hex = lore_mark_verify:kat1_hex(),
    Hex = string_lower(Hex).

kat1_mark_is_62_chars(_) ->
    62 = byte_size(lore_mark_verify:kat1_mark()).

kat1_mark_starts_with_prefix(_) ->
    Mark = lore_mark_verify:kat1_mark(),
    Prefix = lore_mark_verify:mark_prefix(),
    PrefixLen = byte_size(Prefix),
    <<Prefix:PrefixLen/binary, _Rest/binary>> = Mark.

%%--------------------------------------------------------------------
%% kat1/0 drift oracle
%%--------------------------------------------------------------------

kat1_returns_pair(_) ->
    {Hex, Match} = lore_mark_verify:kat1(),
    true = is_binary(Hex),
    true = is_boolean(Match).

kat1_reproduces_against_literal(_) ->
    {Hex, true} = lore_mark_verify:kat1(),
    Hex = lore_mark_verify:kat1_hex().

kat1_reproduces_against_independent_hmac(_) ->
    Input = <<16#01, 0:256>>,
    Digest = crypto:mac(hmac, sha256, <<>>, Input),
    Expected = bin_to_hex_lower(Digest),
    {Hex, _} = lore_mark_verify:kat1(),
    Hex = Expected,
    Expected = lore_mark_verify:kat1_hex().

%%--------------------------------------------------------------------
%% sign + round-trip
%%--------------------------------------------------------------------

sign_returns_binary(_) ->
    Mark = dev_mark(),
    true = is_binary(Mark),
    62 = byte_size(Mark).

sign_kat1_inputs_produce_kat1_mark(_) ->
    %% The cohort-canonical property: sign with KAT-1 inputs -> KAT1_MARK.
    Mark = lore_mark_verify:sign(<<>>, <<>>, <<0:256>>),
    Mark = lore_mark_verify:kat1_mark().

sign_round_trip_verifies(_) ->
    Mark = dev_mark(),
    {ok, verified} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Mark, ?DEV_KEY, dev_corpus()).

sign_bad_corpus_length_throws(_) ->
    try
        _ = lore_mark_verify:sign(?DEV_PAYLOAD, ?DEV_KEY, <<0:128>>),
        ct:fail("expected badarg")
    catch
        error:badarg -> ok
    end.

%%--------------------------------------------------------------------
%% verify/4 closed-enum verdicts
%%--------------------------------------------------------------------

verify_ok_round_trip(_) ->
    Mark = dev_mark(),
    {ok, verified} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Mark, ?DEV_KEY, dev_corpus()).

verify_no_prefix_returns_unknown_version(_) ->
    {error, err_unknown_mark_version} =
        lore_mark_verify:verify(?DEV_PAYLOAD, <<"garbage">>, ?DEV_KEY, dev_corpus()).

verify_v2_prefix_returns_unknown_version(_) ->
    {error, err_unknown_mark_version} =
        lore_mark_verify:verify(
            ?DEV_PAYLOAD, <<"lore@v2:abc">>, ?DEV_KEY, dev_corpus()).

verify_bad_base64_returns_malformed(_) ->
    Prefix = lore_mark_verify:mark_prefix(),
    %% 54 chars but contains '!', not a base64url alphabet char.
    Body = <<"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!">>,
    Bad = <<Prefix/binary, Body/binary>>,
    {error, err_malformed_mark} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Bad, ?DEV_KEY, dev_corpus()).

verify_padding_rejected_returns_malformed(_) ->
    Valid = dev_mark(),
    %% Append a '=' -- strict no-padding base64url rejects it.
    Padded = <<Valid/binary, "=">>,
    {error, err_malformed_mark} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Padded, ?DEV_KEY, dev_corpus()).

verify_short_body_returns_malformed(_) ->
    Prefix = lore_mark_verify:mark_prefix(),
    %% Less than 54 encoded body chars.
    Short = <<Prefix/binary, "AAAA">>,
    {error, err_malformed_mark} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Short, ?DEV_KEY, dev_corpus()).

verify_long_body_returns_malformed(_) ->
    Prefix = lore_mark_verify:mark_prefix(),
    %% More than 54 encoded body chars.
    Long = <<Prefix/binary,
             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">>,
    {error, err_malformed_mark} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Long, ?DEV_KEY, dev_corpus()).

verify_wrong_corpus_returns_corpus_mismatch(_) ->
    Mark = dev_mark(),
    OtherCorpus = crypto:hash(sha256, <<"different-corpus">>),
    {error, err_corpus_mismatch} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Mark, ?DEV_KEY, OtherCorpus).

verify_corpus_mismatch_before_signature_mismatch(_) ->
    Mark = dev_mark(),
    OtherCorpus = crypto:hash(sha256, <<"different-corpus">>),
    OtherKey = <<"different-key">>,
    %% Both wrong -- but cheap-to-expensive surfaces corpus first.
    {error, err_corpus_mismatch} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Mark, OtherKey, OtherCorpus).

verify_wrong_key_returns_signature_mismatch(_) ->
    Mark = dev_mark(),
    OtherKey = <<"iik_dev_DIFFERENT_KEY">>,
    {error, err_signature_mismatch} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Mark, OtherKey, dev_corpus()).

verify_wrong_payload_returns_signature_mismatch(_) ->
    Mark = dev_mark(),
    OtherPayload = <<"different payload">>,
    {error, err_signature_mismatch} =
        lore_mark_verify:verify(OtherPayload, Mark, ?DEV_KEY, dev_corpus()).

verify_bad_corpus_length_throws(_) ->
    Mark = dev_mark(),
    try
        _ = lore_mark_verify:verify(?DEV_PAYLOAD, Mark, ?DEV_KEY, <<0:128>>),
        ct:fail("expected badarg")
    catch
        error:badarg -> ok
    end.

%%--------------------------------------------------------------------
%% verify/2 convenience (implicit KAT-1 fixture)
%%--------------------------------------------------------------------

verify2_kat1_round_trip(_) ->
    %% verify/2 uses implicit Key=<<>>, CorpusSha=<<0:256>>. So the KAT-1
    %% mark with empty payload MUST verify.
    {ok, verified} =
        lore_mark_verify:verify(<<>>, lore_mark_verify:kat1_mark()).

verify2_garbage_returns_unknown_version(_) ->
    {error, err_unknown_mark_version} =
        lore_mark_verify:verify(<<"payload">>, <<"garbage">>).

%%--------------------------------------------------------------------
%% extract/1
%%--------------------------------------------------------------------

extract_kat1_mark(_) ->
    {ok, Parts} = lore_mark_verify:extract(lore_mark_verify:kat1_mark()),
    {mark_parts, <<"v1">>, CorpusPrefix, Digest} = Parts,
    8 = byte_size(CorpusPrefix),
    32 = byte_size(Digest),
    <<0:64>> = CorpusPrefix,
    %% Digest hex MUST equal KAT1 hex.
    DigestHex = bin_to_hex_lower(Digest),
    DigestHex = lore_mark_verify:kat1_hex().

extract_returns_mark_parts(_) ->
    Mark = dev_mark(),
    {ok, _Parts} = lore_mark_verify:extract(Mark).

extract_no_prefix_returns_unknown_version(_) ->
    {error, err_unknown_mark_version} = lore_mark_verify:extract(<<"garbage">>),
    {error, err_unknown_mark_version} = lore_mark_verify:extract(<<"lore@v2:abc">>),
    {error, err_unknown_mark_version} = lore_mark_verify:extract(<<>>).

extract_bad_base64_returns_malformed(_) ->
    Prefix = lore_mark_verify:mark_prefix(),
    Bad = <<Prefix/binary,
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!">>,
    {error, err_malformed_mark} = lore_mark_verify:extract(Bad).

extract_corpus_prefix_matches_input(_) ->
    Mark = dev_mark(),
    Corpus = dev_corpus(),
    {ok, Parts} = lore_mark_verify:extract(Mark),
    {mark_parts, _, CorpusPrefix, _} = Parts,
    <<Expected:8/binary, _/binary>> = Corpus,
    Expected = CorpusPrefix.

%%--------------------------------------------------------------------
%% OTP-28 prefix-pattern build-break regression
%%
%% The as-shipped verify_with_prefix/4 and extract/1 matched on
%%   <<(?MARK_PREFIX):PrefixLen/binary, Encoded/binary>>
%% where ?MARK_PREFIX expands to the literal <<"lore@v1:">> and
%% PrefixLen is a runtime variable. On OTP 28 (and the rule has always
%% held: "a literal string in a binary pattern must not have a type or
%% a size") erlc rejects this as `illegal pattern`, so NO .beam is
%% produced and the entire SDK is non-buildable. The whole suite is
%% the discrimination proof (it cannot load without a compiled module),
%% but this case pins the BEHAVIOUR of the corrected prefix-match path:
%% an exact 8-byte prefix is accepted on the happy path, and a prefix
%% that differs in only the final byte must be rejected as an unknown
%% mark version (proving the `MarkPrefix =:= Prefix` guard still
%% enforces an exact, full-prefix match -- not a mere length match).
%%--------------------------------------------------------------------

otp28_prefix_pattern_match_path(_) ->
    Prefix = lore_mark_verify:mark_prefix(),
    8 = byte_size(Prefix),
    Mark = dev_mark(),

    %% Happy path: the corrected variable-sized prefix segment + equality
    %% guard accepts the exact "lore@v1:" prefix in BOTH the verify/4 and
    %% extract/1 patterns.
    {ok, verified} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Mark, ?DEV_KEY, dev_corpus()),
    {ok, _Parts} = lore_mark_verify:extract(Mark),

    %% Tamper ONLY the final prefix byte (':' -> ';'), keeping the byte
    %% length identical. A bare variable-sized segment would still bind
    %% (same length) -- the `=:= Prefix` guard is what rejects it. Both
    %% entrypoints MUST return err_unknown_mark_version.
    <<Head:7/binary, $:>> = Prefix,
    WrongPrefix = <<Head/binary, $;>>,
    8 = byte_size(WrongPrefix),
    <<_OldPrefix:8/binary, Encoded/binary>> = Mark,
    Tampered = <<WrongPrefix/binary, Encoded/binary>>,
    8 = byte_size(Tampered) - byte_size(Encoded),
    {error, err_unknown_mark_version} =
        lore_mark_verify:verify(?DEV_PAYLOAD, Tampered, ?DEV_KEY, dev_corpus()),
    {error, err_unknown_mark_version} =
        lore_mark_verify:extract(Tampered).

%%--------------------------------------------------------------------
%% Internal helpers
%%--------------------------------------------------------------------

bin_to_hex_lower(Bin) when is_binary(Bin) ->
    iolist_to_binary([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).

string_lower(Bin) when is_binary(Bin) ->
    iolist_to_binary(string:lowercase(Bin)).

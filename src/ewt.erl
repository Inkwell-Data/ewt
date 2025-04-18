-module(ewt).
-include("ewt.hrl").
-define(TYPE, 'EWT').
-define(HMAC_VSN_OLD, hmac_vsn_old).
-define(HMAC_VSN_NEW23, hmac_vsn_new23).
-define(HMAC_VSN_AUTO, hmac_vsn_auto).
-compile({nowarn_removed, [{crypto, hmac, 3}]}).
-compile({nowarn_deprecated_function, [{crypto, hmac, 3}]}).


-ifdef(RUNTIME_OTP_VSN).
-define(HMAC_VSN, ?HMAC_VSN_AUTO).
-else.

-ifdef(OTP_RELEASE).
	-if(?OTP_RELEASE >= 23).
		-define(HMAC_VSN, ?HMAC_VSN_NEW23).
	-else.
		-define(HMAC_VSN, ?HMAC_VSN_OLD).
	-endif.

-else.
	-define(HMAC_VSN, ?HMAC_VSN_OLD).
-endif.

-endif.

-include_lib("eunit/include/eunit.hrl").


-export([token/4, claims/2, token_dated/4, claims_dated/2]).

token_dated(Expiration, Claims_, Key, Alg) ->
	Now = integer_to_binary(calendar:datetime_to_gregorian_seconds(calendar:universal_time())),
	<<Now/binary, ".", (token(Expiration, Claims_, Key, Alg))/binary>>.

token(Expiration, Claims_, Key, Alg) ->
	Claims = Claims_#{exp => exp(Expiration)},
	Header = #{typ => ?TYPE, alg => alg(Alg)},

	B64Header = base64:encode(term_to_binary(Header)),
	B64Claims = base64:encode(term_to_binary(Claims)),

	Payload = payload(B64Header, B64Claims),

	B64Signature = sign(?TYPE, alg(Alg), Payload, Key),

	<<Payload/binary, ".", B64Signature/binary>>.


claims_dated(Token, Key) ->
	claims(Token, Key, dated).


claims(Token, Key) ->
	claims(Token, Key, standard).

claims(Token, Key, Mode) ->
	case catch parse(Token, Key, Mode) of
		expired -> expired;
		{ok, Claim} -> {ok, Claim};
		_ -> bad
	end.


parse(Token, Key, dated) ->
	[_Date, Rest] = binary:split(Token, <<".">>),
	parse(Rest, Key, standard);

parse(Token, Key, standard) ->
	[B64Header, B64Claims, B64Signature] = binary:split(Token, <<".">>, [global]),
	#{typ := Type, alg := Alg} = binary_to_term(base64:decode(B64Header), [safe]),
	true = B64Signature == sign(Type, Alg, B64Header, B64Claims, Key),
	Claims = binary_to_term(base64:decode(B64Claims), [safe]),
	check_expired(Claims).


check_expired(#{exp := Exp} = Claims) ->
	Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
	check_expired(Claims, Now, Exp).

check_expired(_Claims, Now, Exp) when Now > Exp -> expired;
check_expired(Claims, _Now, _Exp) -> {ok, Claims}.

sign(?TYPE, Alg, Header, Claims, Key) ->
	Payload = payload(Header, Claims),
	sign(?TYPE, Alg, Payload, Key).
sign(?TYPE, Alg, Payload, Key) ->
	base64:encode(hmac(Alg, Key, Payload)).

payload(Header, Claims) ->
	<<Header/binary, ".", Claims/binary>>.

alg(auto) -> ?DEFAULT_ALG;
alg(Alg) -> Alg.

exp(auto) -> ?DEFAULT_EXP;
exp(Exp) -> Exp.





hmac(Alg, Key, Payload) ->
	hmac(?HMAC_VSN, Alg, Key, Payload).


hmac(?HMAC_VSN_NEW23, Alg, Key, Payload) ->
	crypto:mac(hmac, Alg, Key, Payload);

hmac(?HMAC_VSN_OLD, Alg, Key, Payload) ->
	crypto:hmac(Alg, Key, Payload);

hmac(?HMAC_VSN_AUTO, Alg, Key, Payload) ->
	OTPRelease = erlang:system_info(otp_release),
	Vsn = if
			  OTPRelease >= "23" -> ?HMAC_VSN_NEW23;
			  true -> ?HMAC_VSN_OLD
		  end,
	hmac(Vsn, Alg, Key, Payload).


-ifdef(TEST).
token_test_() ->
	[
		?_assert(
			ewt:token(100000000000, #{user => <<"John Doe">>, roles => [manager, admin]}, <<"sosecret">>, sha256)
			=:= <<"g3QAAAACZAADYWxnZAAGc2hhMjU2ZAADdHlwZAADRVdU.g3QAAAADZAADZXhwbgUAAOh2SBdkAAVyb2xlc2wAAAACZAAHbWFuYWdlcmQABWFkbWluamQABHVzZXJtAAAACEpvaG4gRG9l.9hBuyowRO6BkCPdt6yd4CPpJ3JovJCONjlrP3gIZOPU">>)
	].

claims_test_() ->
	[
		?_assert(
			ewt:claims(<<"g3QAAAACZAADYWxnZAAGc2hhMjU2ZAADdHlwZAADRVdU.g3QAAAADZAADZXhwbgUAAOh2SBdkAAVyb2xlc2wAAAACZAAHbWFuYWdlcmQABWFkbWluamQABHVzZXJtAAAACEpvaG4gRG9l.9hBuyowRO6BkCPdt6yd4CPpJ3JovJCONjlrP3gIZOPU">>,
					   <<"sosecret">>) =:= {ok,#{exp => 100000000000, roles => [manager,admin], user => <<"John Doe">>}}),
		?_assert(
			ewt:claims(<<"g3QAAAACZAADYWxnZAAGc2hhMjU2ZAADdHlwZAADRVdU.g3QAAAADZAADZXhwYQBkAAVyb2xlc2wAAAACZAAHbWFuYWdlcmQABWFkbWluamQABHVzZXJtAAAACEpvaG4gRG9l.ItidyKytW_LXpF1jILg0w4LX10KI_wqOYumB1CJ98EU">>,
					   <<"sosecret">>) =:= expired),
		?_assert(
			ewt:claims(<<"invalid_token">>,
					   <<"sosecret">>) =:= bad),
		?_assert(
			ewt:claims(<<"g3QAAAACZAADYWxnZAAGc2hhMjU2ZAADdHlwZAADRVdU.g3QAAAADZAADZXhwbgUAAOh2SBdkAAVyb2xlc2wAAAACZAAHbWFuYWdlcmQABWFkbWluamQABHVzZXJtAAAACEpvaG4gRG9l.9hBuyowRO6BkCPdt6yd4CPpJ3JovJCONjlrP3gIZOPU">>,
					   <<"notsosecret">>) =:= bad)
	].

-endif.
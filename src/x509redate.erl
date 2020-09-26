-module(x509redate).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

%% API exports
-export([main/1]).

%%====================================================================
%% API functions
%%====================================================================

%% escript Entry point
main([Cert, Issuer, Days]) ->
    application:ensure_all_started(public_key),
    write_pem(redate(der_cert_of_pem(Cert),
		     key_of_pem(Issuer),
		     erlang:list_to_integer(Days)),
	      Cert),
    erlang:halt(0);
main(_) ->
    Sn = filename:basename(escript:script_name()),
    io:format("usage: ~s CertPemFile IssuerKeyPemFile DaysValid~n~n", [Sn]).


%%====================================================================
%% Internal functions
%%====================================================================
key_of_pem(PemFile) ->
    {ok, Bin} = file:read_file(PemFile),
    lists:keyfind('RSAPrivateKey', 1,
		  lists:map(fun public_key:pem_entry_decode/1,
				     public_key:pem_decode(Bin))).

der_cert_of_pem(PemFile) ->
    {ok, Bin} = file:read_file(PemFile),
    {_, DERCert, not_encrypted} =
	lists:keyfind('Certificate', 1, public_key:pem_decode(Bin)),
    DERCert.

write_pem(DERCert, PemFile) ->
    Bin = public_key:pem_encode([{'Certificate', DERCert, not_encrypted}]),
    file:write_file(PemFile, Bin).

redate(DERCert, #'RSAPrivateKey'{} = Key, Days) ->
    NotAfter =calendar:gregorian_days_to_date(
		calendar:date_to_gregorian_days(date()) + Days),
    Validity = #'Validity'{ notBefore = fmtDate(date()),
			    notAfter = fmtDate(NotAfter) },
    #'OTPCertificate'{tbsCertificate = Tbs} =
	public_key:pkix_decode_cert(DERCert, otp),
    public_key:pkix_sign(Tbs#'OTPTBSCertificate'{ validity = Validity}, Key).

fmtDate({Year, Month, Day}) ->
    {generalTime,
     lists:flatten(io_lib:format("~w~2..0w~2..0w000001Z",[Year, Month, Day]))}.

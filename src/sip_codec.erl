%%%----------------------------------------------------------------------
%%% File    : sip_codec.erl
%%% Author  : Shuai Li <lishuaihenu@gmail.com>
%%% Purpose : IMS/VoLTE SIP codec module
%%% Created : 2013-08-01 by Shuai Li <lishuaihenu@gmail.com>
%%%----------------------------------------------------------------------

-module(sip_codec).
-author('<lishuaihenu@gmail.com>').

-include("sip.hrl").

-compile(export_all).
-compile({no_auto_import, [integer_to_binary/1,
			   binary_to_integer/1,
			   float_to_binary/1,
			   binary_to_float/1
			  ]}).

%%%----------------------------------------------------------------------
%%% Exported functions
%%%----------------------------------------------------------------------

%%-export([encode/1,
%%         decode/1,
%%         cseq/2,
%%         via/2,
%%         address/3,
%%         security/2,
%%         integer_to_binary/1,
%%         binary_to_integer/1,
%%         format_uri/1
%%        ]).

%%% ----------------------------------------------------------------------------
%%% Function: encode(SipMsg) -> SipBinary
%%%
%%% Types: SipMsg     = SIP record, see mod_Sip_msg.hrl
%%%        SipBinary  = binary
%%%
%%% Description: Encodes the given SIP message into a binary.
%%% ----------------------------------------------------------------------------

encode(SipMsg) ->
    case SipMsg of
        #sip_request{} ->
            encode_request(SipMsg);

        #sip_response{} ->
	    encode_response(SipMsg);

        _ ->
            other
    end.

encode_request(Request) ->
    #sip_request{method = Method,
		 uri    = URI,
		 header = Header,
		 body   = Body
		} = Request,

    URIBin = format_uri(URI),
    MethodBin = format_name(Method),
    Top = <<MethodBin/binary, " ", URIBin/binary, " ", ?SIPVERSION>>,

    HeaderBin = format_headers(Header),
    iolist_to_binary([Top, <<"\r\n">>, HeaderBin, <<"\r\n">>, Body]).

encode_response(Response) ->
    #sip_response{status = Status,
		  reason = Reason,
		  header = Header,
		  body   = Body
		 } = Response,

    StatusStr = integer_to_binary(Status),
    ReasonBin = format_name(Reason),
    Top = <<?SIPVERSION, " ", StatusStr/binary, " ", ReasonBin/binary>>,

    HeaderBin = format_headers(Header),
    iolist_to_binary([Top, <<"\r\n">>, HeaderBin, <<"\r\n">>, Body]).

%%% ----------------------------------------------------------------------------
%%% Function: decode(SipBinary) -> {ok, SipMesg} | {fault, Reason}
%%%
%%% Types: SipMsg    = SIP record, see mod_Sip_msg.hrl
%%%        SipBinary = binary
%%%        Reason    = xxxxxxxx
%%%
%%% Description: Encodes the given SIP message into a binary.
%%% ----------------------------------------------------------------------------

decode(SipMsg) ->
    {Pos, _Length} = binary:match(SipMsg, <<"\r\n\r\n">>),
    Pos2 = Pos + 2,
    <<Top:Pos2/binary, "\r\n", Body/binary>> = SipMsg,
    [Start, HeadersBin] = binary:split(Top, <<"\r\n">>),
    Headers = parse_headers(HeadersBin),

    Msg = parse_start_line(Start),
    Msg2 = set_headers(Msg, Headers),

    %% RFC 3261 18.3
    case content_length(Headers) of
	%% Content-Length is present
        {ok, ContentLength} when ContentLength =< size(Body) ->
            <<Body2:ContentLength/binary, _/binary>> = Body,
	    Msg3 = set_body(Msg2, Body2),
	    {ok, dispatch(Msg3)};
        {ok, _} ->
            {content_too_small, Msg2};
	%% Content-Length is not present
        false ->
            {ok, set_body(Msg2, Body)}
    end.


%% Request-Line   =  Method SP Request-URI SP SIP-Version CRLF
%% Status-Line  =  SIP-Version SP Status-Code SP Reason-Phrase CRLF
%% start-line   =  Request-Line / Status-Line

%% RFC3261 7.1: The SIP-Version string is case-insensitive, but implementations MUST send upper-case.
parse_start_line(StartLine) when is_binary(StartLine) ->
    %% split on three parts
    [First, Rest] = binary:split(StartLine, <<" ">>),
    [Second, Third] = binary:split(Rest, <<" ">>),
    case {First, Second, Third} of
        {MethodBin, RequestURI, <<?SIPVERSION>>} ->
            #sip_request{method = parse_method(MethodBin),
                         uri = RequestURI};

        {<<?SIPVERSION>>, <<A,B,C>>, ReasonPhrase} when
	      $1 =< A andalso A =< $6 andalso % 1xx - 6xx
	      $0 =< B andalso B =< $9 andalso
	      $0 =< C andalso C =< $9 ->
            #sip_response{status = list_to_integer([A, B, C]),
                          reason = ReasonPhrase}
    end.


content_length(Headers) ->
    case lists:keyfind('content-length', 1, Headers) of
        false -> false;
        {_Name, Length} -> {ok, binary_to_integer(Length)}
    end.

%% Parse method given in binary format into atom
parse_method(Bin) when is_binary(Bin) ->
    case to_upper(Bin) of
        <<"ACK">>       -> 'ACK';       % RFC3261
        <<"BYE">>       -> 'BYE';       % RFC3261
        <<"CANCEL">>    -> 'CANCEL';    % RFC3261
        <<"INFO">>      -> 'INFO';      % RFC6086
        <<"INVITE">>    -> 'INVITE';    % RFC3261, RFC6026
        <<"MESSAGE">>   -> 'MESSAGE';   % RFC3428
        <<"NOTIFY">>    -> 'NOTIFY';    % RFC3265
        <<"OPTIONS">>   -> 'OPTIONS';   % RFC3261
        <<"PRACK">>     -> 'PRACK';     % RFC3262
        <<"PUBLISH">>   -> 'PUBLISH';   % RFC3903
        <<"REFER">>     -> 'REFER';     % RFC3515
        <<"REGISTER">>  -> 'REGISTER';  % RFC3261
        <<"SUBSCRIBE">> -> 'SUBSCRIBE'; % RFC3265
        <<"UPDATE">>    -> 'UPDATE'     % RFC3311
    end.


%% Set headers to SIP request/response
set_headers(#sip_request{} = Msg, Header) -> Msg#sip_request{header = Header};
set_headers(#sip_response{} = Msg, Header) -> Msg#sip_response{header = Header}.

%% Set body to SIP request/response
set_body(#sip_request{} = Msg, Body) when is_binary(Body) -> Msg#sip_request{body = Body};
set_body(#sip_response{} = Msg, Body) when is_binary(Body) -> Msg#sip_response{body = Body}.


%% Parse required headers
dispatch(#sip_request{} = Msg) ->
    URI = parse_uri(Msg#sip_request.uri),
    Header = pre_parse_headers(Msg#sip_request.header),
    Msg#sip_request{uri = URI, header = Header};

%% Parse response headers
dispatch(#sip_response{} = Msg) ->
    Header = pre_parse_headers(Msg#sip_response.header),
    Msg#sip_response{header = Header}.

%%% ----------------------------------------------------------------------------
%%% format/parse SIP Name    
%%% name <-> binary
%%% ----------------------------------------------------------------------------
format_name(Name) when is_binary(Name) ->
    Name;
format_name(Name) when is_atom(Name) ->
    atom_to_binary(Name, utf8).

%% If atom matching binary name exist, atom is returned. Otherwise, binary is returned as-is.
parse_name(Bin) ->
    try binary_to_existing_atom(Bin, utf8)
    catch error:badarg -> Bin
    end.

%%% ----------------------------------------------------------------------------
%%% format/parse URI
%%% ----------------------------------------------------------------------------
format_uri(URI) when is_binary(URI) ->
    URI;
format_uri(#sip_uri{scheme = sip} = URI) ->
    append_userinfo(URI, <<"sip:">>).

append_userinfo(#sip_uri{user = <<>>} = URI, Bin) ->
    append_hostport(URI, Bin);
append_userinfo(#sip_uri{user = User} = URI, Bin) ->
    append_password(URI, <<Bin/binary, User/binary>>).

append_password(#sip_uri{password = <<>>} = URI, Bin) ->
    append_hostport(URI, <<Bin/binary, $@>>);
append_password(#sip_uri{password = Password} = URI, Bin) ->
    append_hostport(URI, <<Bin/binary, $:, Password/binary, $@>>).

append_hostport(URI, Bin) ->
    Host = format_ip_addr(URI#sip_uri.host),
    append_port(URI, <<Bin/binary, Host/binary>>).


append_port(#sip_uri{port = undefined} = URI, Bin) ->
    append_params(URI, URI#sip_uri.params, Bin);
append_port(#sip_uri{port = Port} = URI, Bin) ->
    append_params(URI, URI#sip_uri.params, <<Bin/binary, $:, (integer_to_binary(Port))/binary>>).


append_params(URI, [{Name, Value} | Tail], Bin) ->
    NameBin = format_name(Name),
    Bin2 = <<Bin/binary, $;, NameBin/binary, $=, Value/binary>>,
    append_params(URI, Tail, Bin2);
append_params(URI, [Name | Tail], Bin) ->
    NameBin = format_name(Name),
    Bin2 = <<Bin/binary, $;, NameBin/binary>>,
    append_params(URI, Tail, Bin2);
append_params(URI, [], Bin) ->
    append_headers(URI#sip_uri.headers, $?, Bin).


append_headers([], _Sep, Bin) ->
    Bin;
append_headers([{Name, Value} | Tail], Sep, Bin) ->
    NameBin = format_name(Name),
    Bin2 = <<Bin/binary, Sep, NameBin/binary, $=, Value/binary>>,
    append_headers(Tail, $&, Bin2).


%% If URI could not be parsed because scheme is not supported, a binary is returned as is.
parse_uri(<<"sip:", URI/binary>>) ->
    case binary:split(URI, <<$@>>) of
	[UserInfo, Rest] ->
	    case binary:split(UserInfo, <<$:>>) of
		[User, Password] -> ok;
		[User] -> Password = <<>>
	    end;
	[Rest] ->
	    User = <<>>,
	    Password = <<>>
    end,
    {Host, Port, ParamsBin} = parse_host_port(Rest),
    {Params, HeadersBin} = parse_uri_params(ParamsBin, []),
    Headers = case HeadersBin of
		  <<>> -> [];
		  _    -> parse_uri_headers(HeadersBin)
	      end,
    #sip_uri{scheme = sip,
	     user = User,
	     password = Password,
	     host = Host,
	     port = Port,
	     params = Params,
	     headers = Headers};

parse_uri(Bin) when is_binary(Bin) ->
    Bin.

%% Parse SIP URI parameters lists
%% param-unreserved  =  "[" / "]" / "/" / ":" / "&" / "+" / "$"
parse_uri_params(<<$;, Bin/binary>>, List) ->
    Pred = fun ($;) -> true; % next parameter
	       ($?) -> true; % headers
	       ($=) -> true; % value
	       (_) -> false
           end,
    {Param, Rest} =
        case parse_until(Bin, Pred) of
            {Name, <<$=, Bin2/binary>>} ->
		%% parse value
                {Value, R} = parse_until(Bin2, Pred),
                {{parse_name(Name), Value}, R};
            {Name, Bin2} ->
		%% no value
                {parse_name(Name), Bin2}
        end,
    parse_uri_params(Rest, [Param|List]);
parse_uri_params(Bin, List) ->
    {lists:reverse(List), Bin}.


%% Parse SIP URI headers
%% headers         =  "?" header *( "&" header )
%% header          =  hname "=" hvalue
%% hname           =  1*( hnv-unreserved / unreserved / escaped )
%% hvalue          =  *( hnv-unreserved / unreserved / escaped )
%% hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
%% unreserved      =  alphanum / mark
%% mark            =  "-" / "_" / "." / "!" / "~" / "*" / "'"
%%                    / "(" / ")"
%% escaped         =  "%" HEXDIG HEXDIG
parse_uri_headers(<<>>) -> [];
parse_uri_headers(<<$?, Bin/binary>>) ->
    Headers = [binary:split(Header, <<$=>>) || Header <- binary:split(Bin, <<$&>>)],
    [{parse_name(Name), Value} || [Name, Value] <- Headers].

%%% ----------------------------------------------------------------------------
%%% format/parse Header
%%% ----------------------------------------------------------------------------
format_headers(Headers) ->
    << <<(process(fn, Name, ignore))/binary, ": ",
         (format(Name, Value))/binary, "\r\n">> ||
	{Name, Value} <- Headers>>.

%% Format header value into the binary.
format(Name, [Value]) ->
    process(f, Name, Value);
format(Name, [Top | Rest]) ->
    TopBin = process(f, Name, Top),
    lists:foldl(fun(Elem, Bin) ->
			ElemBin = process(f, Name, Elem),
			<<Bin/binary, ?COMMA, ?SP, ElemBin/binary>>
		end, TopBin, Rest);
format(Name, Value) ->
    process(f, Name, Value).


%% Split binary into list of headers
%%
%% Convert binary containing headers into list of non-parsed headers (with binary values).
%% Binary must contain a sequence headers, each header terminated by `CRLF'.
%% Empty binary is valid argument that results in empty list returned.
parse_headers(<<>>) -> [];
parse_headers(Headers) when is_binary(Headers) ->
    Pos = size(Headers) - 2,
    <<Headers2:Pos/binary, "\r\n">> = Headers,
    Lines = binary:split(Headers2, <<"\r\n">>, [global]),
    lists:reverse(lists:foldl(fun (Bin, List) ->
				      fold_header(Bin, List)
			      end, [], Lines)).

%% RFC 3261, 7.3.1
%% The line break and whitespace at the beginning of next line are treated as a single SP character.
%% This function appends such lines to the last header.
fold_header(<<C/utf8, _/binary>> = Line, [{Name, Value} | Tail]) when C =:= ?SP; C =:= ?HTAB ->
    Line2 = trim_leading(Line),
    Value2 = trim_trailing(Value),
    [{Name, <<Value2/binary, ?SP, Line2/binary>>} | Tail];

fold_header(HeaderLine, List) ->
    [Name, Value] = binary:split(HeaderLine, <<?HCOLON>>),
    Name2 = to_lower(trim_trailing(Name)),
    Name3 = process(pn, Name2, ignored),
    [{Name3, trim_leading(Value)} | List].


pre_parse_headers(Headers) ->
    %% TODO: Catch incorrect headers and report as bad request/response
    Fun =
        fun({Name, Value}) when Name =:= to; Name =:= from; Name =:= cseq; Name =:= 'call-id';
                                Name =:= 'max-forwards'; Name =:= via; Name =:= 'contact';
				Name =:= 'p-associated-uri'; Name =:= 'security-server';
				Name =:= 'www-authenticate' ->
                {Name, parse(Name, Value)};
           (Other) -> Other
        end,
    lists:map(Fun, Headers).

%% Parse binary header value into the Erlang term representation
%% See type specification for information about which term is used to represent particular header value.
parse(Name, Bin) -> process(p, Name, Bin).

%% Multi-headers parse helper
parse_list(_Name, Top, <<>>) -> [Top];
parse_list(Name, Top, <<?COMMA, Rest/binary>>) -> [Top | parse(Name, Rest)].

%%% ----------------------------------------------------------------------------
%%% Parse/format header name/value
%%% p: parse;  f: format; fn: format name; pn: parse name
%%% ----------------------------------------------------------------------------
process(p, _Name, Header) when not is_binary(Header) ->
    Header; % already parsed
process(f, _Name, Value) when is_binary(Value) ->
    Value; % already formatted

%% 20.7 Authorization
process(fn, 'authorization', _Ignore) -> <<"Authorization">>;
process(p, 'authorization', Bin) ->
    {SchemeBin, Bin2} = parse_token(Bin),
    %% parse scheme, the rest is list of paris param=value
    Scheme = parse_name(SchemeBin),
    auth(Scheme, parse_auths(Bin2));

process(f, 'authorization', Auth) when is_record(Auth, sip_hdr_auth) ->
    SchemeBin = format_name(Auth#sip_hdr_auth.scheme),
    [First | Rest] = Auth#sip_hdr_auth.params,
    FirstBin = format_auth(First),
    lists:foldl(fun(Val, Acc) ->
			<<Acc/binary, ?COMMA, ?SP, (format_auth(Val))/binary>>
		end, <<SchemeBin/binary, ?SP, FirstBin/binary>>, Rest);

%% 20.8 Call-ID
process(pn, <<"i">>, _Ignore) -> 'call-id';
process(fn, 'call-id', _Ignore) -> <<"Call-ID">>;
process(p, 'call-id', Bin) -> Bin;

%% 20.10 Contact
process(pn, <<"m">>, _Ignore) -> 'contact';
process(fn, 'contact', _Ignore) -> <<"Contact">>;
process(p, 'contact', <<"*">>) -> '*';
process(p, 'contact', Bin) ->
    {Top, Rest} = parse_address(Bin, fun parse_contact_param/2),
    parse_list('contact', Top, Rest);

process(f, 'contact', '*') -> <<"*">>;
process(f, 'contact', Addr) when is_record(Addr, sip_hdr_address) ->
    format_address(Addr);

%% 20.14 Content-Length
process(pn, <<"l">>, _Ignore) -> 'content-length';
process(fn, 'content-length', _Ignore) -> <<"Content-Length">>;
process(p, 'content-length', Bin) ->
    binary_to_integer(Bin);

process(f, 'content-length', Length) when is_integer(Length) ->
    integer_to_binary(Length);

%% 20.15 Content-Type
process(pn, <<"c">>, _Ignore) -> 'content-type';
process(fn, 'content-type', _Ignore) -> <<"Content-Type">>;
process(p, 'content-type', Bin) ->
    {Media, <<>>} = parse_media_range(Bin, fun parse_generic_param/2),
    Media;

process(f, 'content-type', CType) when is_record(CType, sip_hdr_mediatype) ->
    Type = format_name(CType#sip_hdr_mediatype.type),
    SubType = format_name(CType#sip_hdr_mediatype.subtype),
    format_params(<<Type/binary, ?SLASH, SubType/binary>>, CType#sip_hdr_mediatype.params);

%% 20.16 CSeq
process(fn, 'cseq', _Ignore) -> <<"CSeq">>;
process(p, 'cseq', Bin) ->
    {Sequence, Bin2} = parse_integer(Bin),
    {MethodBin, <<>>} = parse_token(Bin2),
    Method = parse_name(to_upper(MethodBin)),
    cseq(Sequence, Method);

process(f, 'cseq', CSeq) when is_record(CSeq, sip_hdr_cseq) ->
    SequenceBin = integer_to_binary(CSeq#sip_hdr_cseq.sequence),
    MethodBin = format_name(CSeq#sip_hdr_cseq.method),
    <<SequenceBin/binary, " ", MethodBin/binary>>;

%% 20.19 Expires
process(fn, 'expires', _Ignore) -> <<"Expires">>;
process(p, 'expires', Bin) ->
    binary_to_integer(Bin);

process(f, 'expires', Length) when is_integer(Length) ->
    integer_to_binary(Length);

%% 20.20 From
process(pn, <<"f">>, _Ignore) -> 'from';
process(fn, 'from', _Ignore) -> <<"From">>;
process(p, 'from', Bin) ->
    {Top, <<>>} = parse_address(Bin, fun parse_generic_param/2),
    Top;

process(f, 'from', Addr) when is_record(Addr, sip_hdr_address) ->
    format_address(Addr);

%% 20.22 Max-Forwards
process(fn, 'max-forwards', _Ignore) -> <<"Max-Forwards">>;
process(p, 'max-forwards', Bin) ->
    binary_to_integer(Bin);

process(f, 'max-forwards', Hops) when is_integer(Hops) ->
    integer_to_binary(Hops);

%% 3GPP TS 24.228 P-Associated-URI
process(fn, 'p-associated-uri', _Ignore) -> <<"P-Associated-URI">>;
process(p, 'p-associated-uri', Bin) ->
    {Top, Rest} = parse_address(Bin, fun parse_generic_param/2),
    parse_list('p-associated-uri', Top, Rest);

process(f, 'p-associated-uri', URI) when is_record(URI, sip_hdr_address) ->
    format_address(URI);

%% 20.28 Proxy-Authorization
process(fn, 'proxy-authorization', _Ignore) -> <<"Proxy-Authorization">>;
process(p, 'proxy-authorization', Bin) ->
    %% same as Authorization header
    process(p, 'authorization', Bin);

process(f, 'proxy-authorization', Auth) when is_record(Auth, sip_hdr_auth) ->
    %% same as Authorization header
    process(f, 'authorization', Auth);

%% 20.29 Proxy-Require
process(fn, 'proxy-require', _Ignore) -> <<"Proxy-Require">>;
process(p, 'proxy-require', Bin) ->
    {ReqBin, Rest} = parse_token(Bin),
    Ext = parse_name(to_lower(ReqBin)),
    parse_list('require', Ext, Rest);

process(f, 'proxy-require', Bin) ->
    format_name(Bin);

%% 20.32 Require
process(fn, 'require', _Ignore) -> <<"Require">>;
process(p, 'require', Bin) ->
    {ExtBin, Rest} = parse_token(Bin),
    Ext = parse_name(to_lower(ExtBin)),
    parse_list('require', Ext, Rest);

process(f, 'require', Ext) ->
    format_name(Ext);

%% 20.34 Route
process(fn, 'route', _Ignore) -> <<"Route">>;
process(p, 'route', Bin) ->
    {Top, Rest} = parse_address(Bin, fun parse_generic_param/2),
    parse_list('route', Top, Rest);

process(f, 'route', Route) when is_record(Route, sip_hdr_address) ->
    format_address(Route);

%% 3GPP TS 24.228 Security-Client
process(fn, 'security-client', _Ignore) -> <<"Security-Client">>;

process(f, 'security-client', Client) when is_record(Client, sip_hdr_security) ->
    SchemeBin = format_name(Client#sip_hdr_security.scheme),
    format_params(SchemeBin, Client#sip_hdr_security.params);

%% 3GPP TS 24.228 Security-Server
process(fn, 'security-server', _Ignore) -> <<"Security-Server">>;
process(p, 'security-server', Bin) ->
    {SchemeBin, Bin2} = parse_token(Bin),
    Scheme = parse_name(SchemeBin),
    {Params, <<>>} = parse_params(Bin2, fun parse_security_param/2),
    #sip_hdr_security{scheme = Scheme, params = Params};

%% no need to format this value, because we only receive this value.
process(f, 'security-server', Client) when is_record(Client, sip_hdr_security) ->
    SchemeBin = format_name(Client#sip_hdr_security.scheme),
    format_params(SchemeBin, Client#sip_hdr_security.params);

%% 3GPP TS 24.228 Security-Verify
process(fn, 'security-verify', _Ignore) -> <<"Security-Verify">>;

process(f, 'security-verify', Client) when is_record(Client, sip_hdr_security) ->
    SchemeBin = format_name(Client#sip_hdr_security.scheme),
    format_params(SchemeBin, Client#sip_hdr_security.params);

%% 20.37 Supported
process(pn, <<"k">>, _Ignore) -> 'supported';
process(fn, 'supported', _Ignore) -> <<"Supported">>;
process(p, 'supported', Bin) ->
    {ExtBin, Rest} = parse_token(Bin),
    Ext = parse_name(to_lower(ExtBin)),
    parse_list('supported', Ext, Rest);

process(f, 'supported', Ext) ->
    format_name(Ext);

%% 20.39 To
process(pn, <<"t">>, _Ignore) -> 'to';
process(fn, 'to', _Ignore) -> <<"To">>;
process(p, 'to', Bin) ->
    {Top, <<>>} = parse_address(Bin, fun parse_generic_param/2),
    Top;

process(f, 'to', Addr) when is_record(Addr, sip_hdr_address) ->
    format_address(Addr);

%% 20.42 Via
process(pn, <<"v">>, _Ignore) -> 'via';
process(fn, 'via', _Ignore) -> <<"Via">>;
process(p, 'via', Bin) ->
    {{<<"SIP">>, Version, Transport}, Bin2} = parse_sent_protocol(Bin),
    %% Parse parameters (which should start with semicolon)
    {Host, Port, Bin3} = parse_host_port(Bin2),
    {Params, Rest} = parse_params(Bin3, fun parse_via_param/2),

    Top = #sip_hdr_via{transport = Transport,
                       version = Version,
                       host = Host,
                       port = Port,
                       params = Params},
    parse_list('via', Top, Rest);

process(f, 'via', Via) when is_record(Via, sip_hdr_via) ->
    Version = Via#sip_hdr_via.version,
    Transport = to_upper(atom_to_binary(Via#sip_hdr_via.transport, latin1)),
    Bin = <<"SIP/", Version/binary, $/, Transport/binary>>,
    Host = format_ip_addr(Via#sip_hdr_via.host),
    Bin2 =
        case Via#sip_hdr_via.port of
            undefined -> <<Bin/binary, ?SP, Host/binary>>;
            Port -> <<Bin/binary, ?SP, Host/binary, ?HCOLON, (integer_to_binary(Port))/binary>>
        end,
    format_params(Bin2, Via#sip_hdr_via.params);

%% 20.44 WWW-Authenticate
process(fn, 'www-authenticate', _Ignore) -> <<"WWW-Authenticate">>;
process(p, 'www-authenticate', Bin) ->
    %% process(p, 'proxy-authenticate', Bin);  proxy-authorization ekeechn
	process(p, 'proxy-authorization', Bin);

process(f, 'www-authenticate', Auth) when is_record(Auth, sip_hdr_auth) ->
    %% process(f, 'proxy-authenticate', Auth);  proxy-authorization ekeechn
	process(f, 'proxy-authorization', Auth);

%% Default header processing
process(p, _Name, Header) -> 
    Header; % cannot parse, leave as is
process(f, _Name, Value) ->
    format_value(Value); % do our best to format header value
process(pn, Name, _Ignore) when is_binary(Name) ->
    parse_name(Name);
process(fn, Name, _Ignore) when is_binary(Name) ->
    Name;
process(fn, Name, _Ignore) when is_atom(Name) ->
    atom_to_binary(Name, utf8).

%%% ----------------------------------------------------------------------------
%%% Formatting/Parsing authentication/authorization parameters
%%% should be separated for Authentication-Info, Authorization, Proxy-Authenticate ??
%%% ----------------------------------------------------------------------------
format_auth({Name, Value}) ->
    NameBin = format_name(Name),
    ValBin = format_auth(Name, Value),
    <<NameBin/binary, ?EQUAL, ValBin/binary>>.

format_auth(Name, Value) when Name =:= nextnonce; Name =:= nonce; Name =:= cnonce;
			      Name =:= username; Name =:= realm; Name =:= uri;
			      Name =:= opaque; Name =:= domain; Name =:= response ->
    quote_string(Value);
format_auth(qop, [First|Rest]) ->
    %% special case for Proxy-Authenticate, qop is a list
    Acc0 = <<(format_name(First))/binary>>,
    Bin = lists:foldl(fun(QOP, Acc) ->
			      <<Acc/binary, ?COMMA, ?SP, (format_name(QOP))/binary>>
		      end, Acc0, Rest),
    quote_string(Bin);
format_auth(Name, Qop) when Name =:= qop; Name =:= algorithm ->
    format_name(Qop);
%% format_auth(Name, Bin) when Name =:= rspauth; Name =:= response ->
%%     HexStr = binary_to_hexstr(Bin),
%%     quote_string(HexStr);
format_auth(nc, NonceCount) ->
    [NCBin] = io_lib:format("~8.16.0b", [NonceCount]),
    list_to_binary(NCBin);
format_auth(stale, false) -> <<"false">>;
format_auth(stale, true) -> <<"true">>;
format_auth(_Name, Value) when is_binary(Value) ->
    %% arbitrary auth-param
    case need_quoting(Value) of
        true -> quote_string(Value);
        false -> Value
    end.


parse_auths(Bin) ->
    {NameBin, <<?EQUAL, ValueBin/binary>>} = parse_token(Bin),
    Name = parse_name(NameBin),
    {Value, Rest} =
        case Name of
            _ when Name =:= nextnonce; Name =:= nonce; Name =:= cnonce;
                   Name =:= username; Name =:= realm; Name =:= uri;
                   Name =:= opaque; Name =:= domain ->
                parse_quoted_string(ValueBin);
            _ when Name =:= qop, binary_part(ValueBin, {0, 1}) =:= <<?DQUOTE>> ->
		%% special case for Proxy-Authenticate, qop parameter is quoted string
		%% which can contain several qop-value's
                {QOPsBin, R} = parse_quoted_string(ValueBin),
                List = binary:split(QOPsBin, [<<?COMMA>>], [global]),
                QOPs = [parse_name(trim(QOP)) || QOP <- List],
                {QOPs, R};
            _ when Name =:= qop; Name =:= algorithm ->
                {Val, R} = parse_token(ValueBin),
                {parse_name(Val), R};
            _ when Name =:= rspauth; Name =:= response ->
                {Digest, R} = parse_quoted_string(ValueBin),
                {hexstr_to_binary(Digest), R};
	    _ when Name =:= stale ->
                {Stale, R} = parse_token(ValueBin),
                case to_lower(Stale) of
                    <<"false">> -> {false, R};
                    <<"true">> -> {true, R}
                end;
            nc ->
                {NC, R} = parse_while(ValueBin, fun is_alphanum_char/1),
                {list_to_integer(binary_to_list(NC), 16), trim_leading(R)};
	    %% arbitrary auth-param
            _Other ->
                parse_token_or_quoted(ValueBin)
        end,
    Info = {Name, Value},
    case Rest of
        <<>> -> [Info];
        <<?COMMA, Rest2/binary>> ->
            [Info | parse_auths(Rest2)]
    end.

%%% ----------------------------------------------------------------------------
%%% format/parse Header Address (`Contact:', `To:', `From:')
%%% ----------------------------------------------------------------------------
format_address(Addr) ->
    URIBin = format_uri(Addr#sip_hdr_address.uri),
    Bin = case Addr#sip_hdr_address.display_name of
              <<>> ->
		  <<?LAQUOT, URIBin/binary, ?RAQUOT>>;
              DisplayName ->
                  Quoted = quote_string(DisplayName),
                  <<Quoted/binary, " ", ?LAQUOT, URIBin/binary, ?RAQUOT>>
          end,
    format_params(Bin, Addr#sip_hdr_address.params).


parse_address(Bin, ParamFun) ->
    {Display, URI, Bin2} = parse_address_uri(trim_leading(Bin)),
    {Params, Bin3} = parse_params(Bin2, ParamFun),
    Value = address(trim(Display), URI, Params),
    {Value, Bin3}.

parse_address_uri(<<?DQUOTE, _/binary>> = Bin) ->
    %% name-addr with quoted-string display-name
    {Display, <<?LAQUOT, Rest/binary>>} = parse_quoted_string(Bin),
    {URI, <<?RAQUOT, Params/binary>>} = parse_until(Rest, ?RAQUOT),
    {Display, URI, Params};
parse_address_uri(<<?LAQUOT, Rest/binary>>) ->
    %% name-addr without display-name
    {URI, <<?RAQUOT, Params/binary>>} = parse_until(Rest, ?RAQUOT),
    {<<>>, URI, Params};
parse_address_uri(Bin) ->
    %% either addr-spec or name-addr with token-based display-name
    case parse_until(Bin, ?LAQUOT) of
        {_Any, <<>>} ->
	    %% addr-spec: Section 20
	    %% If the URI is not enclosed in angle brackets, any semicolon-delimited
	    %% parameters are header-parameters, not URI parameters.
	    %% so, parse until comma (next header value), space character or semicolon
            Fun = fun (C) -> is_space_char(C) orelse C =:= ?SEMI orelse C =:= ?COMMA end,

            {URI, Params} = parse_until(Bin, Fun),
            {<<>>, URI, Params};

        {Display, <<?LAQUOT, Rest/binary>>} ->
	    %% name-addr with token-based display-name
            {URI, <<?RAQUOT, Params/binary>>} = parse_until(Rest, ?RAQUOT),
            {Display, URI, Params}
    end.

%%% ----------------------------------------------------------------------------
%%% Parse Header accept-range or media-type grammar
%%% ----------------------------------------------------------------------------
parse_media_range(Bin, ParamFun) ->
    {Type2, SubType2, ParamsBin2} =
        case trim_leading(Bin) of
            <<"*/*", ParamsBin/binary>> ->
                {'*', '*', ParamsBin};
	    _ ->
		{TypeBin, <<?SLASH, Bin2/binary>>} = parse_token(Bin),
		Type = parse_name(TypeBin),
		case trim_leading(Bin2) of
		    <<"*", ParamsBin/binary>> -> {Type, '*', ParamsBin};
		    Bin3 ->
			{SubTypeBin, ParamsBin} = parse_token(Bin3),
			SubType = parse_name(SubTypeBin),
			{Type, SubType, ParamsBin}
		end
	end,
    {Params, Rest} = parse_params(ParamsBin2, ParamFun),
    {media(Type2, SubType2, Params), Rest}.

%%% ----------------------------------------------------------------------------
%%% format/parse params
%%% ----------------------------------------------------------------------------
format_params(Bin, Params) ->
    lists:foldl(fun format_param/2, Bin, Params).

%% Format semi-colon separated list of parameters. Each parameter is either binary (name) or
%% tuple of two binaries (parameter name and value).
format_param({Name, Value}, Bin) ->
    Name2 = format_name(Name),

    %% If contains non-token characters, write as quoted string
    Value2 =
        case need_quoting(Value) of
            true -> quote_string(Value);
            false -> format_value(Value)
        end,
    <<Bin/binary, ?SEMI, Name2/binary, ?EQUAL, Value2/binary>>;
format_param(Name, Bin) ->
    Name2 = format_name(Name),
    <<Bin/binary, ?SEMI, Name2/binary>>.


%% Parse parameters lists
%% *( SEMI param )
%% param  =  token [ EQUAL value ]
%% value  =  token / host / quoted-string
parse_params(Bin, ParseFun) ->
    parse_params_loop(trim_leading(Bin), ParseFun, []).

parse_params_loop(<<?SEMI, Bin/binary>>, ParseFun, List) ->
    {NameBin, MaybeValue} = parse_token(Bin),
    Name = parse_name(NameBin),
    case MaybeValue of
        <<?EQUAL, Bin2/binary>> ->  %% Parameter with value
            {Value, Rest} = parse_token_or_quoted(Bin2),
            Prop = {Name, ParseFun(Name, Value)},
            parse_params_loop(Rest, ParseFun, [Prop | List]);
        Rest ->  %% Parameter without a value
            parse_params_loop(Rest, ParseFun, [Name | List])
    end;
parse_params_loop(Bin, _ParseFun, List) ->
    {lists:reverse(List), trim_leading(Bin)}.

%%% ----------------------------------------------------------------------------
%%% Parse functions
%%% ----------------------------------------------------------------------------

%% Parsing
%% Extract `token' from the UTF-8 binary and return the rest. 
%% Note that leading whitespaces are skipped and the rest is returned
%% with leading whitespaces trimmed (rest is either empty binary or
%% starts with non-whitespace character).
parse_token(Bin) ->
    {Token, Rest} = parse_while(trim_leading(Bin), fun is_token_char/1),
    {Token, trim_leading(Rest)}.

parse_token_or_quoted(Bin) ->
    case trim_leading(Bin) of
        <<?DQUOTE, _Rest/binary>> -> parse_quoted_string(Bin);
        _Token -> parse_token(Bin)
    end.

%% Parse IP address
%% IPv4address    =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
%% IPv6address    =  hexpart [ ":" IPv4address ]
%% hexpart        =  hexseq / hexseq "::" [ hexseq ] / "::" [ hexseq ]
%% hexseq         =  hex4 *( ":" hex4)
%% hex4           =  1*4HEXDIG
parse_ip_address(Bin) ->
    inet_parse:address(binary_to_list(Bin)).

%% Parse number from the binary and return the rest
parse_integer(<<C, _/binary>> = Bin) when C >= $0, C =< $9 ->
    parse_integer(Bin, 0).

parse_integer(<<C, Rest/binary>>, Acc) when C >= $0, C =< $9 ->
    parse_integer(Rest, Acc * 10 + (C - $0));
parse_integer(<<Rest/binary>>, Acc) ->
    {Acc, Rest}.

parse_sent_protocol(Bin) ->
    {Protocol, <<$/, Bin2/binary>>} = parse_token(Bin),
    {Version, <<$/, Bin3/binary>>} = parse_token(Bin2),
    {Transport, Bin4} = parse_token(Bin3),
    Transport2 = parse_name(to_lower(Transport)),
    {{Protocol, Version, Transport2}, Bin4}.

%%% ----------------------------------------------------------------------------
%%% Scanning binaries
%%% ----------------------------------------------------------------------------

%% Parse binary while given predicate function evaluates to `true'
parse_while(Bin, Fun) ->
    parse_while(Bin, Fun, 0).

parse_while(Bin, _Fun, Pos) when Pos =:= size(Bin) ->
    {Bin, <<>>};
parse_while(Bin, Fun, Pos) when is_function(Fun) ->
    <<Start:Pos/binary, Char, Rest/binary>> = Bin,
    case Fun(Char) of
        false ->
            {Start, <<Char, Rest/binary>>};
        _ ->
            parse_while(Bin, Fun, Pos + 1)
    end.

%% Parse binary until given predicate function evaluates to `true' or
%% until given character is encountered
parse_until(Bin, Char) when is_integer(Char) ->
    parse_while(Bin, fun (C) -> C =/= Char end, 0);
parse_until(Bin, Fun) when is_function(Fun) ->
    parse_while(Bin, fun (C) -> not Fun(C) end, 0).


%% Parse `host [":" port]' expressions
%% hostport       =  host [ ":" port ]
%% host           =  hostname / IPv4address / IPv6reference
%% hostname       =  *( domainlabel "." ) toplabel [ "." ]
%% domainlabel    =  alphanum
%%                   / alphanum *( alphanum / "-" ) alphanum
%% toplabel       =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
%% IPv4address    =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
%% IPv6reference  =  "[" IPv6address "]"
%% IPv6address    =  hexpart [ ":" IPv4address ]
%% hexpart        =  hexseq / hexseq "::" [ hexseq ] / "::" [ hexseq ]
%% hexseq         =  hex4 *( ":" hex4)
%% hex4           =  1*4HEXDIG
%% port           =  1*DIGIT

parse_host_port(<<"[", Bin/binary>>) ->
    %% IPv6 reference
    IsValidChar = fun ($:) -> true; (C) -> is_alphanum_char(C) end,
    {HostBin, <<"]", Rest/binary>>} = parse_while(Bin, IsValidChar),
    {ok, IPv6} = parse_ip_address(HostBin),
    host_port(IPv6, Rest);
parse_host_port(Bin) ->
    %% host name or IPv4
    IsValidChar = fun ($-) -> true;
    		      ($.) -> true;
		      (C) -> is_alphanum_char(C)
		  end,
    {HostBin, Rest} = parse_while(Bin, IsValidChar),
    case maybe_ipv4(HostBin) of
        true -> {ok, Host} = parse_ip_address(HostBin);
        false -> Host = binary_to_list(HostBin)
    end,
    host_port(Host, Rest).

host_port(Host, <<":", PortBin/binary>>) ->
    {Port, Rest} = parse_integer(PortBin),
    {Host, Port, Rest};
host_port(HostBin, Rest) ->
    {HostBin, undefined, Rest}.

maybe_ipv4(<<>>) -> true;
maybe_ipv4(<<C, Rest/binary>>) when C =:= $. ; C >= $0, C =< $9 ->
    maybe_ipv4(Rest);
maybe_ipv4(_) -> false.

%%% ----------------------------------------------------------------------------
%%% Parse SIP Header parameters
%%% ----------------------------------------------------------------------------

parse_generic_param(_Name, Value) -> Value.

%% Parse contact header parameters
parse_contact_param(q, Value) -> binary_to_float(Value);
parse_contact_param(expires, Value) -> binary_to_integer(Value);
parse_contact_param(_Name, Value) -> Value.

%% Parse standard Via: parameters
parse_via_param(ttl, TTL) -> binary_to_integer(TTL);
parse_via_param(maddr, MAddr) ->
    case parse_ip_address(MAddr) of
        {ok, Addr} -> Addr;
        {error, einval} -> binary_to_list(MAddr)
    end;
parse_via_param(received, Received) ->
    {ok, Addr} = parse_ip_address(Received),
    Addr;
parse_via_param(rport, Value) -> binary_to_integer(Value);
%% maybe we don't care these parameters
parse_via_param(comp, Value) -> binary_to_atom(Value, utf8);
parse_via_param(branch, Value) -> binary_to_atom(Value, utf8);
parse_via_param(_Name, Value) -> Value.

%% Parse contact header parameters
parse_security_param(alg, Value) -> binary_to_atom(Value, utf8);
parse_security_param('spi-c', Value) -> binary_to_integer(Value);
parse_security_param('spi-s', Value) -> binary_to_integer(Value);
parse_security_param('port-c', Value) -> binary_to_integer(Value);
parse_security_param('port-s', Value) -> binary_to_integer(Value);
parse_security_param(_Name, Value) -> Value.

%%% ----------------------------------------------------------------------------
%%% Construct SIP Header
%%% ----------------------------------------------------------------------------

%% Construct address (value of From/To headers).
%% Note: parses URI if it is given in binary form</em>
address(DisplayName, URI, Params) when is_binary(DisplayName), is_list(Params), is_binary(URI) ->
    #sip_hdr_address{display_name = DisplayName, uri = parse_uri(URI), params = Params};

address(DisplayName, URI, Params) when is_binary(DisplayName), is_list(Params) ->
    #sip_hdr_address{display_name = DisplayName, uri = URI, params = Params}.


%% Construct `Authorization:' header value
auth(Scheme, Params) ->
    Params1 = [{Name, check_auth_para(Name, Val)} || {Name, Val} <- Params],
    #sip_hdr_auth{scheme = Scheme, params = Params1}.

check_auth_para(Name, Value) ->
    case Name of
	qop ->
	    Value;
	_ ->
	    if is_binary(Value) -> 
		    Value;
	       is_list(Value) -> 
		    list_to_binary(Value);
	       is_atom(Value) ->
		    atom_to_binary(Value, utf8);
	       true -> 
		    msg_trace:error(?MODULE, "auth/2 found param in wrong format: {~p, ~p}", [Name, Value]),
		    Value
	    end
    end.
	    

%% Construct media type value.
media(Type, SubType, Params) when is_list(Params) ->
    #sip_hdr_mediatype{type = Type, subtype = SubType, params = Params}.

%% Construct `CSeq:' header value.
cseq(Sequence, Method) when is_integer(Sequence),
			    (is_atom(Method) orelse is_binary(Method)) ->
    #sip_hdr_cseq{method = Method, sequence = Sequence}.

%% Construct `Security-Client:' header value.
security(Scheme, Params) ->
    #sip_hdr_security{scheme = Scheme, params = Params}.

%% Construct Via header value.
%% Eg. Host = "fc00:01ab:0121:0000:47cc:2936:aca5:bd0c" || "10.38.236.12" ||
%%            {64512, 427, 289, 0, 18380, 10550, 44197, 48396} || {10, 38, 236, 12}
via({Host, Port}, Params) when is_list(Params), (is_list(Host) orelse is_tuple(Host)) ->
    #sip_hdr_via{host = Host, port = Port, params = Params};

via(Host, Params) when is_list(Host); is_tuple(Host) ->
    via({Host, 5060}, Params).

%%% ----------------------------------------------------------------------------
%%% common function
%%% ----------------------------------------------------------------------------
to_upper(Bin) ->
    << <<(string:to_upper(Char))/utf8>> || <<Char/utf8>> <= Bin >>.

%% Convert binary UTF-8 encoded string to lowercase. Only latin1 characters are actually converted.
to_lower(Bin) ->
    << <<(string:to_lower(Char))/utf8>> || <<Char/utf8>> <= Bin >>.

hexstr_to_binary(<<L, Bin/binary>>) when size(Bin) rem 2 =:= 0 ->
    Byte = int(L),
    hexstr_to_binary(Bin, <<Byte>>);
hexstr_to_binary(Bin) ->
    hexstr_to_binary(Bin, <<>>).

hexstr_to_binary(<<>>, Res) -> Res;
hexstr_to_binary(<<H, L, Rest/binary>>, Res) ->
    Byte = int(H) * 16 + int(L),
    hexstr_to_binary(Rest, <<Res/binary, Byte>>).

binary_to_hexstr(Bin) ->
    binary_to_hexstr(Bin, <<>>).

binary_to_hexstr(<<>>, Res) -> Res;
binary_to_hexstr(<<Byte, Rest/binary>>, Res) ->
    H = hex(Byte div 16),
    L = hex(Byte rem 16),
    binary_to_hexstr(Rest, <<Res/binary, H, L>>).


need_quoting(Value) when not is_binary(Value) -> false; % integer, atom, etc, no quoting
need_quoting(<<>>) -> true;
need_quoting(<<C, Rest/binary>>)  ->
    (not is_token_char(C)) orelse (Rest =/= <<>> andalso need_quoting(Rest)).

%% Generate valid quoted-string by replacing all `\' and `"'.
quote_string(Bin) when is_list(Bin) ->
    quote_string_loop(list_to_binary(Bin), <<?DQUOTE>>);
quote_string(Bin) when is_binary(Bin)->
    quote_string_loop(Bin, <<?DQUOTE>>).

quote_string_loop(<<>>, Acc) ->
    <<Acc/binary, ?DQUOTE>>;
quote_string_loop(<<C, Rest/binary>>, Acc) when C =:= $\\; C =:= $" ->
    quote_string_loop(Rest, <<Acc/binary, $\\, C>>);
quote_string_loop(<<C, Rest/binary>>, Acc) when C >= 16#20 ->
    quote_string_loop(Rest, <<Acc/binary, C>>).

%% quoted-pair    =  "\" (%x00-09 / %x0B-0C
%%                   / %x0E-7F)
%% qdtext         =  LWS / %x21 / %x23-5B / %x5D-7E
%%                   / UTF8-NONASCII
%% quoted-string  =  SWS DQUOTE *(qdtext / quoted-pair ) DQUOTE

%% Parse `quoted-string' from the UTF-8 binary string
%%
%% Extract quoted-string from the UTF-8 binary, unquote it
%% and return the rest. Note that leading whitespaces are skipped and
%% the rest is returned with leading whitespaces trimmed (rest is
%% either empty binary or starts with non-whitespace character).

parse_quoted_string(Bin) ->
    <<?DQUOTE, Bin2/binary>> = trim_leading(Bin),
    parse_quoted_loop(Bin2, <<>>).

parse_quoted_loop(<<?DQUOTE, Rest/binary>>, Acc) ->
    {Acc, trim_leading(Rest)};
parse_quoted_loop(<<$\\, C, Rest/binary>>, Acc) when
      C >= 16#00, C =< 16#09;
      C >= 16#0B, C =< 16#0C;
      C >= 16#0E, C =< 16#7F ->
    parse_quoted_loop(Rest, <<Acc/binary, C>>);
parse_quoted_loop(<<C, Rest/binary>>, Acc) when C =/= $\\ ->
    parse_quoted_loop(Rest, <<Acc/binary, C>>).


%% format unknown parameter value
format_value(Atom) when is_atom(Atom) -> atom_to_binary(Atom, utf8);
format_value(Bin) when is_binary(Bin) -> Bin;
format_value(Int) when is_integer(Int) -> integer_to_binary(Int);
format_value(Float) when is_float(Float) -> float_to_binary(Float);
format_value(List) when is_list(List) -> list_to_binary(List);
format_value({_A, _B, _C, _D} = Addr) -> format_ip_addr(Addr);
format_value({_A, _B, _C, _D, _E, _F, _G, _H} = Addr) -> format_ip_addr(Addr).

format_ip_addr(Str) when is_list(Str) ->
    case string:words(Str, $:) of
	8 ->  %% IPv6
	    <<"[", (list_to_binary(Str))/binary, "]">>;
	_ ->  %% IPv4
	    list_to_binary(Str)
    end;

format_ip_addr({A, B, C, D}) ->
    <<(integer_to_binary(A))/binary, $.,
      (integer_to_binary(B))/binary, $.,
      (integer_to_binary(C))/binary, $.,
      (integer_to_binary(D))/binary>>;

format_ip_addr({A, B, C, D, E, F, G, H}) ->
    Bin1 = hex4(A, <<"[">>),
    Bin2 = hex4(B, <<Bin1/binary, ":">>),
    Bin3 = hex4(C, <<Bin2/binary, ":">>),
    Bin4 = hex4(D, <<Bin3/binary, ":">>),
    Bin5 = hex4(E, <<Bin4/binary, ":">>),
    Bin6 = hex4(F, <<Bin5/binary, ":">>),
    Bin7 = hex4(G, <<Bin6/binary, ":">>),
    Bin8 = hex4(H, <<Bin7/binary, ":">>),
    <<Bin8/binary, "]">>;

format_ip_addr({A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P}) ->
    R1 = A bsl 8 + B,
    R2 = C bsl 8 + D,
    R3 = E bsl 8 + F,
    R4 = G bsl 8 + H,
    R5 = I bsl 8 + J,
    R6 = K bsl 8 + L,
    R7 = M bsl 8 + N,
    R8 = O bsl 8 + P,
    format_ip_addr({R1, R2, R3, R4, R5, R6, R7, R8}).

hex4(N, Bin) ->
    A = hex(N div 4096),
    B = hex((N rem 4096) div 256),
    C = hex((N rem 256) div 16),
    D = hex(N rem 16),
    <<Bin/binary, A, B, C, D>>.

hex(N) when N >= 0, N =< 9 -> N + $0;
hex(N) when N >= 10, N =< 15 -> N - 10 + $a.


int(C) when C >= $0, C =< $9 -> C - $0;
int(C) when C >= $a, C =< $z -> C - $a + 10;
int(C) when C >= $A, C =< $Z -> C - $A + 10.


is_token_char(C) when C =:= $- ; C =:= $. ; C =:= $! ;
		      C =:= $% ; C =:= $* ; C =:= $_ ;
		      C =:= $+ ; C =:= $` ; C =:= $' ;
		      C =:= $~ ->
    true;
is_token_char(C) ->
    is_alphanum_char(C).

is_alphanum_char(C) -> 
    is_alpha_char(C) orelse is_digit_char(C).

is_alpha_char(C) ->
    (C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z).

is_digit_char(C) when C >= $0, C =< $9 -> true;
is_digit_char(_C) -> false.

%% space characters (space, tab, line feed, carriage return)
is_space_char(C) when C =:= $ ; C =:= $\t ; C =:= $\r ; C =:= $\n -> true;
is_space_char(_) -> false.

%% Trim both trailing and leading whitespaces from the binary string
trim(Bin) ->
    trim_trailing(trim_leading(Bin)).

%% Trim leading whitespaces from the binary string
trim_leading(<<>>) -> <<>>;
trim_leading(Bin) ->
    <<C, Rest/binary>> = Bin,
    case Bin of
        <<C, Rest/binary>> when C =:= $ ; C =:= $\t ; C =:= $\r ; C =:= $\n ->
            trim_leading(Rest);
        _Other -> Bin
    end.

%% Trim trailing whitespaces from the binary string
trim_trailing(<<>>) -> <<>>;
trim_trailing(Bin) ->
    Sz = size(Bin) - 1,
    case Bin of
        <<Rest:Sz/binary, C>> when C =:= $ ; C =:= $\t ; C =:= $\r ; C =:= $\n ->
            trim_trailing(Rest);
        _Other -> Bin
    end.

%% OTP-R16B already have these functions !
integer_to_binary(Int) when is_integer(Int) ->
    list_to_binary(integer_to_list(Int)).

binary_to_integer(Bin) when is_binary(Bin) ->
    list_to_integer(binary_to_list(Bin)).

float_to_binary(Float) when is_float(Float) ->
    [Res] = io_lib:format("~.3f", [Float]),
    Bin = list_to_binary(Res),
    Sz1 = size(Bin) - 1,
    Sz2 = Sz1 - 1,
    %% Strip last zeros
    case Bin of
        <<R:Sz2/binary, "00">> -> R;
        <<R:Sz1/binary, "0">> -> R;
        R -> R
    end.

binary_to_float(Bin) when is_binary(Bin) ->
    list_to_float(binary_to_list(Bin)).

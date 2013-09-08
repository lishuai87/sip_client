%%%----------------------------------------------------------------------
%%% File    : test.erl
%%% Author  : Shuai Li <lishuaihenu@gmail.com>
%%% Purpose : test functions for sip codec
%%% Created : 2013-08-01 by Shuai Li <lishuaihenu@gmail.com>
%%%----------------------------------------------------------------------

-module(test).

-include("sip.hrl").

%% test
-export([test/0, server/0, send/1]).

-export([sip_register/0,
	 sip_register/4,
	 sip_response/0
        ]).

%%%----------------------------------------------------------------------
%%% SIP functions
%%%----------------------------------------------------------------------

sip_register() ->
    Method = 'REGISTER',

    URI = #sip_uri{scheme = sip,         % sip
		   user = <<>>,          % binary()
	   	   password = <<>>,      % binary()
		   host = "tcs.ics.se",  % inet:ip_address() | string()
		   port = undefined,     % undefined | 0..65535
		   params = [],          % sip_params()
		   headers = []          % sip_headers()
		  },

    Via_Params = [{comp, sigcomp}, {branch, z9hG4bKnashds7}],

    Header = [{via, [via({{10, 38, 184, 2}, 5060}, Via_Params)]},
	      {'max-forwards', 70},
	      %% {from, address(<<"49165300000027">>, <<"sip:49165300000027@tcs.ics.se">>, [{tag, <<"4fa3">>}])},
	      %% {to, address(<<"49165300000027">>, <<"sip:49165300000027@tcs.ics.se">>, [])},
	      %% {contact, [address(<<"49165300000027">>, <<"sip:49165300000027@10.38.184.2">>, [{expires, 60000}])]},
	      {from, address("xxx", "sip:49165300000027@tcs.ics.se", [{tag, <<"4fa3">>}])},
	      {to, address("sip:49165300000027@tcs.ics.se")},
	      {contact, [address("yyy", "sip:49165300000027@10.38.184.2", [{expires, 60000}])]},
	      {'call-id', 12345678},
	      {'authorization', [auth('Digest', [{realm, <<"register.home1.net">>},
						 {uri, <<"sip:register.home1.net">>},
						 {algorithm, 'MD5'},
						 {reponse, <<>>}])]},
	      
	      {'security-client', [security('ipsec-3gpp', [{alg, <<"hmac-sha-1-96">>},
							   {'spi-c', 23456789},
							   {'spi-s', 12345678},
							   {'port-c', 2468},
							   {'port-s', 1357}])]},
	      {'require', 'sec-agree'},
	      {'proxy-require', 'sec-agree'},
	      {cseq, cseq(12, 'REGISTER')},
	      {supported, 'path'},
	      {'content-length', 0}
	     ],

    Body = <<>>,

    Request = #sip_request{method = Method,
			   uri = URI,
			   header = Header,
			   body = Body},

    Packet = sip_codec:encode(Request),
    binary_to_list(Packet).


sip_register(Method, URI, Header, Body) ->

    Request = #sip_request{method = Method,
			   uri = URI,
			   header = Header,
			   body = Body},

    Packet = sip_codec:encode(Request),
    binary_to_list(Packet).


sip_response() ->

    Via_Params = [{comp, "sigcomp"}, {branch, <<"z9hG4bKnashds7">>}],

    Header = [{via, [via({{10, 38, 184, 2}, 5060}, Via_Params)]},
	      {from, address(<<"49165300000027">>, <<"sip:49165300000027@tcs.ics.se">>, [{tag, <<"4fa3">>}])},
	      {to, address(<<"49165300000027">>, <<"sip:49165300000027@tcs.ics.se">>, [])},
	      {'call-id', 12345678},
	      {cseq, cseq(12, 'REGISTER')},
	      {'content-length', 0}
	     ],
    Body = <<>>,

    Response = #sip_response{status = 401,
			     reason = 'Unauthorized',
			     header = Header,
			     body = Body},

    Packet = sip_codec:encode(Response),
    binary_to_list(Packet).


%%%----------------------------------------------------------------------
%%% SIP header helpers
%%%----------------------------------------------------------------------

%% Construct address (value of From/To headers). Note: parses URI if it is given in binary form
address(DisplayName, URI, Params) when is_list(DisplayName), is_list(URI), is_list(Params) ->
    #sip_hdr_address{display_name = list_to_binary(DisplayName),
		     uri = list_to_binary(URI),
		     params = Params};

address(DisplayName, URI, Params) when is_list(Params) ->
    #sip_hdr_address{display_name = DisplayName,
		     uri = URI,
		     params = Params}.

address(URI) when is_list(URI) ->
    address(<<>>, list_to_binary(URI), []);

address(URI) ->
    address(<<>>, URI, []).

%% Construct `Authorization:' header value
auth(Scheme, Params) ->
    #sip_hdr_auth{scheme = Scheme, params = Params}.

%% Construct `CSeq:' header value.
cseq(Sequence, Method) when is_integer(Sequence), 
			    (is_atom(Method) orelse is_binary(Method)) ->
    #sip_hdr_cseq{sequence = Sequence, method = Method}.

%% Construct media type value.
media(Type, SubType, Params) when is_list(Params) ->
    #sip_hdr_mediatype{type = Type, subtype = SubType, params = Params}.

%% Construct `Security-Client:' header value.
security(Scheme, Params) ->
    #sip_hdr_security{scheme = Scheme, params = Params}.

%% Construct Via header value.
via({Host, Port}, Params) when is_list(Params), (is_list(Host) orelse is_tuple(Host)) ->
    #sip_hdr_via{host = Host, port = Port, params = Params};

via(Host, Params) when is_list(Host); is_tuple(Host) ->
    via({Host, 5060}, Params).


%%%----------------------------------------------------------------------
%%% Test functions
%%%----------------------------------------------------------------------

test() ->
    spawn(?MODULE, server, []),
    spawn(?MODULE, send, [udp]).

server() ->
    {ok, Socket} = gen_udp:open(12345, [binary]),
    loop(Socket).

loop(Socket) ->
    receive
	{udp, Socket, Host, Port, Bin} ->
	    io:format("receive client (~w:~w) msg: ~w~n", [Host, Port, Bin]),
	    <<_UDPheader:8/binary, Msg1/binary>> = Bin,
	    %% {_UDPheader, Msg1} = split_binary(Bin, 8),

	    Msg2 = sip_response(1),
	    Msg3 = sip_response(2),

	    gen_udp:send(Socket, Host, Port, Msg1),
	    timer:sleep(1000),
	    gen_udp:send(Socket, Host, Port, Msg2),
	    timer:sleep(1000),
	    gen_udp:send(Socket, Host, Port, Msg3),
	    loop(Socket)
    end.


send(udp) ->
    RequestMsg = sip_register(),
    UDPpacket = gtp_codec:add_udp_header(1234, 4321, RequestMsg),

    {ok, Socket} = gen_udp:open(0, [binary]),
    gen_udp:send(Socket, "localhost", 12345, UDPpacket),
    receive_msg(Socket);

send(data) ->
    RequestMsg = sip_register(),

    {ok, Socket} = gen_udp:open(0, [binary]),
    gen_udp:send(Socket, "localhost", 12345, RequestMsg),
    receive_msg(Socket);

send(gtp) ->
    RequestMsg = sip_register(),

    MsAddr = [11, 22, 33, 44],
    DestAddr = [10, 20, 30, 40],
    Teid = binary_to_list(<<1:4/unit:8>>),

    UDPpacket = mod_Gtp_msg:set_gtpu_msg(g_pdu, MsAddr, 1234, DestAddr, 4321, Teid, RequestMsg),

    {ok, Socket} = gen_udp:open(0, [binary]),
    gen_udp:send(Socket, "localhost", 12345, UDPpacket),
    receive_msg(Socket).

receive_msg(Socket) ->
    receive
	{udp, Socket, _, _, Bin} ->
	    io:format("receive mesg: ~w~n", [Bin]),
	    ReceiveMsg = sip_codec:decode(Bin),
	    io:format("decode ok: ~w~n", [ReceiveMsg]),
	    receive_msg(Socket)
    after
	3000 ->
	    gen_udp:close(Socket)
    end.

sip_response(1) ->
    Via_Params = [{comp, sigcomp}, {branch, z9hG4bKnashds7}],

    Header = [{via, [via({{10, 38, 184, 2}, 5060}, Via_Params)]},
	      {from, address(<<"49165300000027">>, <<"sip:49165300000027@tcs.ics.se">>, [{tag, <<"4fa3">>}])},
	      {to, address(<<"49165300000027">>, <<"sip:49165300000027@tcs.ics.se">>, [])},
	      {'call-id', 12345678},
	      {cseq, cseq(12, 'REGISTER')},
	      {'content-length', 0}
	     ],
    Body = <<>>,

    Response = #sip_response{status = 401,
			     reason = 'Unauthorized',
			     header = Header,
			     body = Body},

    Packet = sip_codec:encode(Response),
    binary_to_list(Packet);

sip_response(2) ->
    Via_Params = [{comp, sigcomp}, {branch, z9hG4bKnashds7}],

    URI_1 = #sip_uri{user = atom_to_binary('+1-212-555-1111', utf8),
		     host = "home1.net",
		     params = [{user, <<"phone">>}]
		    },

    PAssoc_URI = [address("sip:xxx@xx"), address(URI_1)],

    Header = [{via, [via({{10, 38, 184, 2}, 5060}, Via_Params)]},
	      {from, address(<<"49165300000027">>, <<"sip:49165300000027@tcs.ics.se">>, [{tag, <<"4fa3">>}])},
	      {to, address(<<"49165300000027">>, <<"sip:49165300000027@tcs.ics.se">>, [])},
	      {'call-id', 12345678},
	      {contact, [address("xxx", "sip:xxxx@xxxx", [{expires, 6000}])]},
	      {cseq, cseq(12, 'REGISTER')},
	      {'p-associated-uri', PAssoc_URI},
	      {'content-length', 0}
	     ],
    Body = <<>>,

    Response = #sip_response{status = 200,
			     reason = 'OK',
			     header = Header,
			     body = Body},

    Packet = sip_codec:encode(Response),
    binary_to_list(Packet).

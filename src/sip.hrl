%%%----------------------------------------------------------------------
%%% File    : sip.hrl
%%% Author  : Shuai Li <lishuaihenu@gmail.com>
%%% Purpose : Records used by SIP message.
%%% Created : 2013-08-01 by Shuai Li <lishuaihenu@gmail.com>
%%%----------------------------------------------------------------------

-define(EQUAL, $=).
-define(SP, $ ).
-define(SEMI, $;).
-define(HTAB, $\t).
-define(COMMA, $,).
-define(HCOLON, $:).
-define(DQUOTE, $").
-define(LAQUOT, $<).
-define(RAQUOT, $>).
-define(SLASH, $/).
-define(LPAREN, $().
-define(RPAREN, $)).
-define(SIPVERSION, "SIP/2.0").

%%-----------------------------------------------------------------------
%% SIP message types.
%%-----------------------------------------------------------------------

%% @type sip_request() = #sip_request{}.
%% SIP request record, containing 'method', 'uri', 'header' and 'body'.
-record(sip_request, {
          method,       % atom: 'REGISTER', 'ACK', 'BYE', 'INVITE', 'MESSAGE' etc.
          uri,          % #sip_uri{}
          header = [],
          body = <<>>   % binary()
         }).

-record(sip_response, {
          status,       % integer()
          reason,       % string()
          header = [],  % keylist record()
          body = <<>>   % binary()
         }).

-record(sip_uri, {
	  scheme = sip,
	  user = <<>>,       % binary()
	  password = <<>>,   % binary()
	  host = undefined,  % inet:ip_address() | string()
	  port = undefined,  % undefined | 0..65535
	  params = [],
	  headers = []
	 }).

%% Value for header `Authorization:'
-record(sip_hdr_auth, {
	  scheme,
	  params = []
	 }).

%% Value for address headers (`Route:', `Record-Route', `To:', `From:', `Contact')
-record(sip_hdr_address, {
	  display_name = <<>>,  % binary(), display name is unquoted (all escapes are unescaped)
	  uri = <<>>,           % binary() | #sip_uri{},
	  params = []
	 }).

%% Value for headers `Accept:', ...
-record(sip_hdr_mediatype, {
	  type,        % sip_name(),
	  subtype,     % sip_name(),
	  params = []
	 }).

-record(sip_hdr_cseq, {
	  sequence,  % integer()
	  method     % atom()
	 }).

-record(sip_hdr_via, {
	  version = <<"2.0">>,  % binary(),
	  transport = 'udp',    % since we only use GTP-U UDP payload
	  host,                 % inet:ip_address() | string(), % sent-by hostname
	  port = 'undefined',   % integer() | 'undefined', % sent-by port
	  params = []           % [{'ttl', integer()} |
				%  {'maddr', string() | inet:ip_address()} |
				%  {'received', inet:ip_address()} |
				%  {'branch', binary()} |
				%  {sip_name(), term()} | sip_name()]
	 }).

%%-----------------------------------------------------------------------
%% 3GPP specified data
%%-----------------------------------------------------------------------
-record(sip_hdr_security, {
	  scheme,      % atom()
	  params = []
	 }).

%%-----------------------------------------------------------------
%% SIP transaction layer
%%-----------------------------------------------------------------

%% See RFC 3261, 20.42 Via
-define(MAGIC_COOKIE, "z9hG4bK").

%% Client transaction unique key
-record(sip_tx_client, {
	  branch,  % binary()
	  method   % sip_name()
	 }).

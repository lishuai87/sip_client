%%%----------------------------------------------------------------------
%%% File    : ran.hrl
%%% Author  : Shuai Li
%%% Purpose : General records and constants for RAN simulators
%%% Created : 2013-08-01 by Shuai Li <lishuaihenu@gmail.com>
%%%----------------------------------------------------------------------

%%% =====================================================================
%%% SD's (StateData records)
%%% =====================================================================

%% data for security association
-record(sec_assoc, {
	  spi_uc :: integer(),
	  spi_us :: integer(),
	  spi_pc :: integer(),
	  spi_ps :: integer(),
	  port_uc :: integer(),
	  port_us :: integer(),
	  port_pc :: integer(),
	  port_ps :: integer(),
	  alg,      %% Integrity protection algorithm
	  ealg      %% Encryption algorithm; default is null
	 }).

%% data for IMS capable mobiles.
-record(ims_sd, {
	  impi,          %% :: sip_uri{} private id
	  impu,          %% :: sip_uri{}  public id
	  ueAddr :: list(),           %% should be IPv6 addr [1,2,3,4,5,6,7,8]
	  pcscfAddr :: list(),        %% should be IPv6 addr [1,2,3,4,5,6,7,8]
	  pcscfAddrList :: list(),    %% should be list of IPv6 addr [[1,2,3,4,5,6,7,8], [1,2,3,4,5,6,7,8]]
	  pdpId :: non_neg_integer(), %% the PDP-Index of the default bearer
	  regsState :: undefined|registered|unregistered,
	  secAssoc :: #sec_assoc{},
	  oldSecAssoc :: #sec_assoc{},
	  perRegsStart,
	  perRegsTimer,
	  auth,          %% Authorization data used for Re-registration
	  cseq :: integer(),
	  timerInd :: non_neg_integer(),  %% Timer Index
	  call_id :: atom(),
	  req,           %% keep request msg for resending
	  state,         %% keep current state in the test case
	  ik = [] :: list()                      %% integrity key
	 }).


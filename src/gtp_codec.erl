%%%----------------------------------------------------------------------
%%% File    : gtp_msg.erl
%%% Author  : Shuai Li <lishuaihenu@gmail.com>
%%% Purpose : encode and decode GTP-U message
%%% Created : 2013-08-01 by Shuai Li <lishuaihenu@gmail.com>
%%%----------------------------------------------------------------------

-module(gtp_codec).
-author('<lishuaihenu@gmail.com>').

%% export functions
-compile(export_all).

%%%----------------------------------------------------------------------
%%% Encoding
%%%----------------------------------------------------------------------

set_gtpu_msg(UeAddr, UePort, DestAddr, DestPort, Teid, Userdata) ->
    IPpacket = set_udp_packet(UeAddr, UePort, DestAddr, DestPort, Userdata),

    [2#00110000, %% Version 1 + spare=0 + PT 1 (GTP) + E=0 (No extension) + S=0 + PN=0
     255, %% IEI G-PDU
     length(IPpacket) bsr 8, %% Length 1'st octet
     length(IPpacket) band 16#ff] ++ %% IEs and sequence number length
        Teid ++
        IPpacket.

set_udp_packet(SAddr, SPort, DAddr, DPort, Userdata) ->
    UDPlen = length(Userdata) + 8,
    IPlen = UDPlen + 20,

    IPheaderPart1 = [16#45, %% Version 4, Header length 5
                     16#00, %% Type of Service
                     IPlen bsr 8,
                     IPlen band 16#ff,
                     16#00, 16#00, %% Identification
                     16#00, 16#00, %% Flags 0, Fragment Offset 0
                     16#40, %% Time to live
                     17], %% Protocol = UDP

    %% When calculating the checksum, the value of the checksum field is zero
    Checksum = checksum(IPheaderPart1 ++ [0,0] ++ SAddr ++ DAddr),

    UDPheader = [SPort bsr 8,
                 SPort band 16#ff,
                 DPort bsr 8,
                 DPort band 16#ff,
                 UDPlen bsr 8,
                 UDPlen band 16#ff,
                 0,0], %% No checksum

    IPheaderPart1 ++ Checksum ++ SAddr ++ DAddr ++
        UDPheader ++
        Userdata.

checksum(OctList) ->
    Sum = sum_words(OctList, 0),
    %% The 16-bit addition is performed twice because the first may result in overflow of the 16 bits
    Sum16tmp = (Sum bsr 16) + (Sum band 16#ffff),
    Sum16 = ((Sum16tmp bsr 16) + (Sum16tmp band 16#ffff)) bxor 16#ffff,
    [Sum16 bsr 8, Sum16 band 16#ff].

sum_words([], Sum) ->
    Sum;
sum_words([Oct1,Oct2|Tail], Sum) ->
    sum_words(Tail, Sum + (Oct1 bsl 8) + Oct2).


add_udp_header(SPort, DPort, Userdata) ->
    UDPlen = length(Userdata) + 8,
    UDPheader = [SPort bsr 8,
		 SPort band 16#ff,
		 DPort bsr 8,
		 DPort band 16#ff,
		 UDPlen bsr 8,
		 UDPlen band 16#ff,
		 0, 0],  %% No checksum

    UDPheader ++ Userdata.

drop_udp_header(<<_UDPheader:8/binary, Userdata/binary>>) ->
    Userdata.

sip_client
==========

IMS/VoLTE SIP client, based on RFC 3261 and 3GPP TS 24.229.

This program can never run, because it doesn't contain 3GPP LTE UE functional modules. This program is what we add for LTE UE.

From 3GPP TS 24.228, we can see how a real UE work:<br />
1. Attach to MME<br />
2. Activate IMS PDN, finish P-CSCF discovery<br />
3. IMS registration<br />
4. VoLTE call

What we concern is 3 and 4, the SIP signalling is over the top of EPS GTP-U payload.

Many thanks to siperl and yxa.
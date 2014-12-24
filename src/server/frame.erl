-module(frame).
-export([decode/2, encode/2]).

-import(log, [log/3, log/2]).

-include("frame.hrl").

decode(Packet, Context) ->
	decode(v1, Packet, Context).

encode(Frame, Context) ->
	encode(v1, Frame, Context).


decode(v1, Packet, Context) ->
	<<1:8, Encrypt:3, _Reserved:5, CryptedFrameBody/binary>> = Packet,
	FrameBody =  mycrypt:decrypt_frame_body(CryptedFrameBody, Encrypt, config:get(sharedkey, Context)),
	case FrameBody of
		<<0:1/big-integer, FlowID:31/big-integer, Data/binary>> ->	% Matches data msg
			{data, FlowID, Data};
		<<1:1/big-integer, ?OP_TRUNK_CONFIG:31/big-integer, Certificate/binary>> ->	% Matches ctl msg OP_TRUNCER_CONFIG
			{ctl, trunk, config, Certificate};	% This message is always uncrypted plain.
		<<1:1/big-integer, ?OP_TRUNK_OK:31/big-integer, SharedKey/binary>> ->	% Matches ctl msg OP_TRUNCER_OK
			{ctl, trunk, ok, [mycrypt:decrypt_shared_key(SharedKey, config:get(privkey, Context))]};
		<<1:1/big-integer, ?OP_TRUNK_FAILURE:31/big-integer, ErrorMsg/binary>> ->
			{ctl, trunk, failure, [ErrorMsg]};
		<<1:1/big-integer, ?OP_FLOW_OPEN:31/big-integer, FlowID:32/big-integer, HTTPRequestHeader/binary>> ->
			{ctl, flow, open, [FlowID, Encrypt, HTTPRequestHeader]};
		<<1:1/big-integer, ?OP_FLOW_CLOSE:31/big-integer, FlowID:32/big-integer>> ->
			{ctl, flow, close, [FlowID, Encrypt]};
		<<1:1/big-integer, ?OP_FLOW_FAILURE:31/big-integer, FlowID:32/big-integer, ErrorMsg/binary>> ->
			{ctl, flow, failure, [FlowID, Encrypt, ErrorMsg]};
		% TODO: to be continued.
		_ ->
			{error, "Unknown Frame format."}
	end.

encode(v1, {data, FlowID, CryptFlag, RawData}, Context) ->
	RawBody = <<0:1/big-integer, FlowID:31/big-integer, RawData/binary >>,
	CryptedBody =  mycrypt:encrypt_frame_body(RawBody, CryptFlag, config:get(sharedkey, Context)),
	{ok, <<1:8/big-integer, CryptFlag:3/big-integer, 0:5/big-integer, CryptedBody/binary>>};
encode(v1, {ctl, trunk, config, [Certificate]}, _Context) ->
	Frame_body = <<1:1/big-integer, ?OP_TRUNK_CONFIG:31/big-integer, Certificate/binary >>,
	{ok, <<1:8/big-integer, 0:3/big-integer, 0:5/big-integer, Frame_body/binary>>};
encode(v1, {ctl, trunk, ok, [Encrypted_shared_key]}, _Context) ->
	Frame_body = <<1:1/big-integer, ?OP_TRUNK_OK:31/big-integer, Encrypted_shared_key/binary >>,
	{ok, <<1:8/big-integer, 0:3/big-integer, 0:5/big-integer, Frame_body/binary>>};
encode(v1, {ctl, trunk, failure, [ErrorMsg]}, _Context) ->
	Frame_body = <<1:1/big-integer, ?OP_TRUNK_FAILURE:31/big-integer, ErrorMsg/binary >>,
	{ok, <<1:8/big-integer, 0:3/big-integer, 0:5/big-integer, Frame_body/binary>>};
encode(v1, {ctl, flow, open, [FlowID, CryptFlag, HTTPReqHeader]}, Context) ->
	Rawbody = <<1:1/big-integer, ?OP_FLOW_OPEN:31/big-integer, FlowID:32/big-integer, HTTPReqHeader/binary>>,
	Frame_body = mycrypt:encrypt_frame_body(Rawbody, CryptFlag, config:get(sharedkey, Context)),
	{ok, <<1:8/big-integer, CryptFlag:3/big-integer, 0:5/big-integer, Frame_body/binary>>};
encode(v1, {ctl, flow, failure, [FlowID, CryptFlag, ErrorMsg]}, Context) ->
	Raw_body = <<1:1/big-integer, ?OP_FLOW_FAILURE:31/big-integer, FlowID:32/big-integer, ErrorMsg/binary>>,
	Frame_body = mycrypt:encrypt_frame_body(Raw_body, CryptFlag, config:get(sharedkey, Context)),
	{ok, <<1:8/big-integer, CryptFlag:3/big-integer, 0:5/big-integer, Frame_body/binary>>};
encode(v1, {ctl, flow, close, [FlowID, CryptFlag]}, Context) ->
	Raw_body = <<1:1/big-integer, ?OP_FLOW_CLOSE:31/big-integer, FlowID:32/big-integer>>,
	Frame_body = mycrypt:encrypt_frame_body(Raw_body, CryptFlag, config:get(sharedkey, Context)),
	{ok, <<1:8/big-integer, CryptFlag:3/big-integer, 0:5/big-integer, Frame_body/binary>>};
% TODO: to be continued.
encode(v1, {ctl, Level, Code, _Args}, _Context) ->
	log(log_error, "Don't know how to encode ~p/~p message.", [Level, Code]),
	{error, "Don't know how to encode."}.


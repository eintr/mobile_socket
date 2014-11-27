-module(frame).
-export([decode/2, encode/2]).

-import(log, [log/3, log/2]).

-include("frame.hrl").

decode(Packet, Context) ->
	decode(v1, Packet, Context).

encode(Frame, Context) ->
	encode(v1, Frame, Context).


decode(v1, Packet, Context) ->
	<<1:8, Encrypt:3, Prio:3, _Reserved:2, CryptedFrameBody/binary>> = Packet,
	FrameBody =  mycrypt:decrypt_frame_body(CryptedFrameBody, Encrypt, config:config(sharedkey, Context)),
	case FrameBody of
		<<0:1, FlowID:31, Data/binary>> ->	% Matches data msg
			{data, Prio, FlowID, Data};
		<<1:1, ?OP_TRUNK_OK:31, SharedKey/binary>> ->	% Matches ctl msg OP_TRUNCER_OK
			{ctl, truncer, ok, [mycrypt:decrypt_shared_key(SharedKey, config:config(privkey, Context))]};
		<<1:1, ?OP_TRUNK_FAILURE:31, ErrorMsg/binary>> ->
			{ctl, truncer, failure, [ErrorMsg]};
		<<1:1, ?OP_FLOW_OPEN:31, FlowID:32/big-integer, HTTPRequestHeader/binary>> ->
			{ctl, flow, open, [Prio, FlowID, HTTPRequestHeader]};
		<<1:1, ?OP_FLOW_CLOSE:31, FlowID:32/big-integer>> ->
			{ctl, flow, close, [FlowID]};
		<<1:1, ?OP_FLOW_FAILURE:31, FlowID:32/big-integer, ErrorMsg/binary>> ->
			{ctl, flow, failure, [FlowID, ErrorMsg]};
		% TODO: to be continued.
		_ ->
			{error, "Unknown Frame format."}
	end.

encode(v1, {data, Prio, FlowID, RawData}, Context) ->
	CryptedData = mycrypt:encrypt_frame_body(RawData, 1, config:config(sharedkey, Context)),
	Frame_body = <<0:1, FlowID:31, CryptedData/binary >>,
	{ok, <<(length(Frame_body)+2):16/big-integer, 1:8, 1:3, Prio:3, 0:2>>};
%encode(v1, {ctl, truncer, init, [ClientCookie]}, Context) ->
%	Frame_body = <<0:1, ?OP_TRUNCER_INIT:31, ClientCookie:32/big-integer >>,
%	{ok, <<(length(Frame_body)+2):16/big-integer, 1:8, 0:3, 4:3, 0:2>>};
encode(v1, {ctl, trunk, config, [Certificate]}, _Context) ->
	Frame_body = <<0:1, ?OP_TRUNCER_CONFIG:31, Certificate/binary >>,
	{ok, <<(length(Frame_body)+2):16/big-integer, 1:8, 0:3, 4:3, 0:2>>};
encode(v1, {ctl, trunk, ok, [ClientCookie, Encrypted_shared_key]}, _Context) ->
	Frame_body = <<0:1, ?OP_TRUNCER_CONFIG:31, ClientCookie:32/big-integer, Encrypted_shared_key/binary >>,
	{ok, <<(length(Frame_body)+2):16/big-integer, 1:8, 0:3, 4:3, 0:2>>};
encode(v1, {ctl, trunk, failure, [ErrorMsg]}, _Context) ->
	Frame_body = <<0:1, ?OP_TRUNCER_CONFIG:31, ErrorMsg/binary >>,
	{ok, <<(length(Frame_body)+2):16/big-integer, 1:8, 0:3, 4:3, 0:2>>};
encode(v1, {ctl, flow, open, [Prio, FlowID, HTTPReqHeader]}, Context) ->
	Raw_body = <<0:1, ?OP_FRAMER_OPEN:31, FlowID:32/big-integer, HTTPReqHeader/binary>>,
	Frame_body = mycrypt:encrypt_frame_body(Raw_body, 1, config:config(sharedkey, Context)),
	{ok, <<(length(Frame_body)+2):16/big-integer, 1:8, 0:3, Prio:3, 0:2>>};
encode(v1, {ctl, flow, failure, [FlowID, ErrorMsg]}, Context) ->
	Raw_body = <<0:1, ?OP_FRAMER_FAILURE:31, FlowID:32/big-integer, ErrorMsg/binary>>,
	Frame_body = mycrypt:encrypt_frame_body(Raw_body, 1, config:config(sharedkey, Context)),
	{ok, <<(length(Frame_body)+2):16/big-integer, 1:8, 0:3, 4:3, 0:2>>};
encode(v1, {ctl, flow, close, [FlowID]}, Context) ->
	Raw_body = <<0:1, ?OP_FRAMER_FAILURE:31, FlowID:32/big-integer>>,
	Frame_body = mycrypt:encrypt_frame_body(Raw_body, 1, config:config(sharedkey, Context)),
	{ok, <<(length(Frame_body)+2):16/big-integer, 1:8, 0:3, 4:3, 0:2>>};
% TODO: to be continued.
encode(v1, {ctl, Level, Code, _Args}, _Context) ->
	log(log_error, "Don't know how to encode ~p/~p message.", [Level, Code]),
	{error, "Don't know how to encode."}.


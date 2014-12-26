-module(frame).
-export([decode/2, encode/2]).

-import(log, [log/3, log/2]).

-include("frame.hrl").

decode(Packet, Context) ->
	decode(v1, Packet, Context).

encode(Frame, Context) ->
	encode(v1, Frame, Context).


decode(v1, Packet, Context) ->
	<<1:3, Encrypt:2, Zip:1, _Reserved:2, CryptedFrameBody/binary>> = Packet,
	FrameBody =  mycrypt:decrypt_frame_body(CryptedFrameBody, Encrypt, Zip, config:get(sharedkey, Context)),
	case FrameBody of
		<<0:1/big-integer, FlowID:15/big-integer, Data/binary>> ->	% Matches data msg
			{data, FlowID, Encrypt, Zip, Data};
		<<1:1/big-integer, ?OP_SOCKET_CERT_REQ:15/big-integer, _/binary>> ->
			{ctl, socket, cert_req, {}};
		<<1:1/big-integer, ?OP_SOCKET_CERT:15/big-integer, Certificate/binary>> ->
			{ctl, socket, cert, {zlib:unzip(Certificate)}};
		<<1:1/big-integer, ?OP_SOCKET_KEY_SYNC:15/big-integer, CRC32:32/big-integer, SharedKey/binary>> ->
			{ctl, socket, key_sync, {CRC32, mycrypt:decrypt_shared_key(SharedKey, config:get(privkey, Context))}};
		<<1:1/big-integer, ?OP_SOCKET_KEY_REJ:15/big-integer, _/binary>> ->
			{ctl, socket, key_rej, {}};
		<<1:1/big-integer, ?OP_PIPELINE_OPEN:15/big-integer, FlowID:16/big-integer, MaxDelay:16/big-integer, ReplyFLag:8/big-integer, Data/binary>> ->
			{ctl, flow, open, {FlowID, Encrypt, Zip, MaxDelay, ReplyFLag, Data}};
		<<1:1/big-integer, ?OP_PIPELINE_CLOSE:15/big-integer, FlowID:16/big-integer>> ->
			{ctl, flow, close, {FlowID}};
		% TODO: to be continued.
		_ ->
			{error, "Unknown Frame format."}
	end.

encode(v1, {data, FlowID, CryptFlag, Zip, RawData}, Context) ->
	RawBody = <<	0:1/big-integer,
					FlowID:15/big-integer,
					RawData/binary >>,
	CryptedBody =  mycrypt:encrypt_frame_body(RawBody, CryptFlag, Zip, config:get(sharedkey, Context)),
	{ok, <<1:3/big-integer, CryptFlag:2/big-integer, Zip:1/big-integer, 0:2/big-integer, CryptedBody/binary>>};
encode(v1, {ctl, socket, cert_req, _}, _Context) ->
	Frame_body = <<	1:1/big-integer,
					?OP_SOCKET_CERT_REQ:15/big-integer>>,
	{ok, <<1:3/big-integer, 0:2/big-integer, 0:1/big-integer, 0:2/big-integer, Frame_body/binary>>};
encode(v1, {ctl, socket, cert, {CertificateBin}}, _Context) ->
	Frame_body = <<	1:1/big-integer,
					?OP_SOCKET_CERT:15/big-integer,
					(zlib:zip(CertificateBin))/binary >>,
	{ok, <<1:3/big-integer, 0:2/big-integer, 0:1/big-integer, 0:2/big-integer, Frame_body/binary>>};
encode(v1, {ctl, socket, key_sync, {CRC32, Encrypted_shared_key}}, _Context) ->
	Frame_body = <<	1:1/big-integer,
					?OP_SOCKET_KEY_SYNC:15/big-integer,
					CRC32:32/big-integer,
					Encrypted_shared_key/binary>>,
	{ok, <<1:3/big-integer, 0:2/big-integer, 0:1/big-integer, 0:2/big-integer, Frame_body/binary>>};
encode(v1, {ctl, socket, key_rej, _}, _Context) ->
	Frame_body = <<	1:1/big-integer,
					?OP_SOCKET_KEY_REJ:15/big-integer>>,
	{ok, <<1:3/big-integer, 0:2/big-integer, 0:1/big-integer, 0:2/big-integer, Frame_body/binary>>};
encode(v1, {ctl, pipeline, open, {FlowID, CryptFlag, Zip, MaxDelay, ReplyFlags, Data}}, Context) ->
	Rawbody = <<	1:1/big-integer,
					?OP_PIPELINE_OPEN:15/big-integer,
					FlowID:32/big-integer,
					MaxDelay:16/big-integer,
					ReplyFlags:16/big-integer,
					Data/binary>>,
	Frame_body = mycrypt:encrypt_frame_body(Rawbody, CryptFlag, Zip, config:get(sharedkey, Context)),
	{ok, <<1:3/big-integer, CryptFlag:2/big-integer, Zip:1/big-integer, 0:2/big-integer, Frame_body/binary>>};
encode(v1, {ctl, pipeline, close, [FlowID, CryptFlag, Zip]}, Context) ->
	Raw_body = <<1:1/big-integer, ?OP_PIPELINE_CLOSE:15/big-integer, FlowID:16/big-integer>>,
	Frame_body = mycrypt:encrypt_frame_body(Raw_body, CryptFlag, Zip, config:get(sharedkey, Context)),
	{ok, <<1:3/big-integer, CryptFlag:2/big-integer, Zip:1/big-integer, 0:2/big-integer, Frame_body/binary>>};

% TODO: to be continued.
encode(v1, {ctl, Level, Code, _Args}, _Context) ->
	log(log_error, "Don't know how to encode ~p/~p message.", [Level, Code]),
	{error, "Don't know how to encode."}.


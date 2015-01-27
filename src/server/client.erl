-module(client).
-behaviour(gen_fsm).

-include_lib("public_key/include/public_key.hrl").
-include_lib("kernel/include/inet.hrl").

-export([run/2, start_link/2]).
-export([init/1, code_change/4, handle_event/3, handle_info/3, handle_sync_event/4, terminate/3]).
-export([prepare/2, recv_config/2, trunk_ok/2, create_flow/2, main_loop/2]).


-define(PREINSTALLED_CERT, <<"
-----BEGIN CERTIFICATE-----
MIIC5DCCAk2gAwIBAgIJAK6g3HiskNGKMA0GCSqGSIb3DQEBCwUAMIGKMQswCQYD
VQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamluZzEOMAwG
A1UECgwFV2VpYm8xDzANBgNVBAsMBmVybGFuZzENMAsGA1UEAwwESm9objEnMCUG
CSqGSIb3DQEJARYYaGFpcWluZzFAc3RhZmYud2VpYm8uY29tMB4XDTE0MTIyNDA3
MDcxNloXDTQyMDUxMTA3MDcxNlowgYoxCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdC
ZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMQ4wDAYDVQQKDAVXZWlibzEPMA0GA1UE
CwwGZXJsYW5nMQ0wCwYDVQQDDARKb2huMScwJQYJKoZIhvcNAQkBFhhoYWlxaW5n
MUBzdGFmZi53ZWliby5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ32
5Sa8X8VbxpX+5gjVm9b3uJKKJeCpAGu7dcqgzCpnFAqWwcZWzc31kzJsQzoYZwG/
BmB0vevYuMbAJcBQ/NnzKwifaCXdR1o55gA5goeCkiZVtIR9LinKEgFzN4QqZSrt
lF5gCVRslGkIDJFJDOfhT6c85MXTC9hZihpeMIS9AgMBAAGjUDBOMB0GA1UdDgQW
BBThCk2eoN+F9LodfGtcNYaHPRmGmjAfBgNVHSMEGDAWgBThCk2eoN+F9LodfGtc
NYaHPRmGmjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAJVRXYV3d2ou
D40YUseGZjy7XX0vLfIRc1OiWY5Wv+Fri0b3TljQbJrI81vBtCUP5FkzczRaPOSf
tkBpLm6eoPGAKPmmXBw2WKI2HvHcwb98n4J9it/IlIUIJ7PoUIvHveXR2bTpH1qj
TmMrnjGdXB4RLwofb5L5VutQYblOq/Hg
-----END CERTIFICATE-----
">>).


run(IP, Port) ->
	ok = crypto:start(),
	{ok, Pid} = start_link({IP, Port}, [{request, <<"GET /\r\n\r\n">>}, {output, "/tmp/out1"}]),
	gen_fsm:send_event(Pid, go),
	loop(Pid).

loop(Pid) ->
	receive
		_ -> loop(Pid)
	end.

start_link({IP, Port}, Config) ->
	gen_fsm:start_link(?MODULE, [{IP, Port}, Config], []).

init([{IP, Port}, Config]) ->
	[{'Certificate', Cert, not_encrypted}] = public_key:pem_decode(?PREINSTALLED_CERT),
	CertRec = public_key:pkix_decode_cert(Cert, otp),
	CA_PUBKEY = ((CertRec#'OTPCertificate'.tbsCertificate)#'OTPTBSCertificate'.subjectPublicKeyInfo)#'OTPSubjectPublicKeyInfo'.subjectPublicKey,
	io:format("Loaded CA pubkey.\n"),
	{ok, Socket} = gen_tcp:connect(IP, Port, [binary, {packet, 2}, {active, false}]),
	io:format("Connected to ~p:~p\n", [IP, Port]),
	{ok, prepare, {Socket, Config, [{ca_pubkey, CA_PUBKEY}]}}.

prepare(go, {TrunkSocket, Config, Context}=_State) ->
	inet:setopts(TrunkSocket, [{active, true}]),
	create_flow(goto, {TrunkSocket, Config, Context}).
%	{next_state, recv_config, {TrunkSocket, Config, Context++[{flowtable, []}]}}.

recv_config({tcp, TrunkSocket, Frame}, {TrunkSocket, Config, Context}=_State) ->
	io:format("recv_config({tcp, ...)\n"),
	case frame:decode(Frame, Context) of
		{ctl, trunk, config, Certificate} ->
			io:format("Received server certificate.\n"),
			%[{'Certificate', Cert, not_encrypted}] = public_key:pem_decode(Certificate),
			case public_key:pkix_verify(Certificate, config:get(ca_pubkey, Context)) of
				false -> {stop, "Server certificate verify failed."};
				true ->
					io:format("Server certificate verify Passed.\n"),
					trunk_ok(goto, {TrunkSocket, Config, config:set({pub_key, mycrypt:extract_pubkey(Certificate)}, Context)})
			end;
		Msg ->
			io:format("Got a ~p while expecting {ctl, trunk, config}\n", [Msg])
	end;
recv_config({tcp_closed, TrunkSocket}, {TrunkSocket, Config, Context}=_State) ->
	{stop, "Peer closed."};
recv_config(_UnkownMsg, State) ->
	io:format("UnkownMsg: ~p\n", [_UnkownMsg]),
	{stop, normal, State}.

trunk_ok(goto, {TrunkSocket, Config, Context}=_State) ->
	Shared_key = mycrypt:rand_sharedkey(),
	io:format("Random sharedkey=~p\n", [Shared_key]),
	NewContext = config:set({sharedkey, Shared_key}, Context),
	Encrypted_shared_key = mycrypt:encrypt_shared_key(Shared_key, config:get(pub_key, Context)),
	{ok, Bin} = frame:encode({ctl, trunk, ok, [Encrypted_shared_key]}, NewContext),
	ok = gen_tcp:send(TrunkSocket, Bin),
	{ok, OutFile} = file:open("/tmp/out1", [write]),
	io:format("CTL_TRUNC_OK sent.\n"),
	create_flow(goto, {TrunkSocket, Config, NewContext++[{outfile1, OutFile}]}).

create_flow(goto, {TrunkSocket, _Config, Context}=_State) ->
	NewContext = config:set({cryptflag, 0}, Context),
	{ok, Bin} = frame:encode({ctl, pipeline, open, {1, 0, 1, 0, 0, <<>>}}, NewContext),
	ok = gen_tcp:send(TrunkSocket, Bin),
	io:format("ctl/pipeline/open msg sent\n"),

	{ok, Bin2} = frame:encode({data, 1, 0, 0, <<"GET /\r\n\r\n">>}, NewContext),
	ok = gen_tcp:send(TrunkSocket, Bin2),
	io:format("HTTP Req msg sent~p\n", [Bin]),

	{next_state, main_loop, {TrunkSocket, _Config, NewContext}}.

main_loop({tcp_closed, TrunkSocket}, {TrunkSocket, _Config, _Context}=State) ->
	io:format("Socket closed by peer.\n"),
	{stop, normal, State};
main_loop({tcp, TrunkSocket, Frame}, {TrunkSocket, _Config, Context}=State) ->
	case frame:decode(Frame, Context) of
		{data, 1, CryptFlag, Zip, Data} ->
			io:format("Got data./n"),
			file:write(config:get(outfile1, Context), Data),
			{next_state, main_loop, State, 5000};
		{data, Flowid, CryptFlag, Data} ->
			io:format("?? Got data in incorrect flowid(~p): ~p\n", [Flowid, Data]),
			{next_state, main_loop, State, 5000};
		{ctl, trunk, failure, [ErrorMsg]} ->
			io:format("?? Trunk failed:~p\n", [ErrorMsg]),
			{stop, normal, State};
		{ctl, pipeline, close, _} ->
			io:format("Received {ctl, flow, close, _}.\n"),
			{stop, normal, State};
		{ctl, pipeline, failure, [FlowID, ErrorMsg]} ->
			io:format("Flow ~p closed abnormally: ~p\n", [FlowID, ErrorMsg]),
			{stop, normal, State};
		_Msg ->
			io:format("Unknown Message:~p\n", [_Msg]),
			{next_state, main_loop, State, 5000}
	end.

terminate(Reason, _StateName, {TrunkSocket, _Config, Context}=_State) ->
	gen_tcp:close(TrunkSocket),
	file:close(config:get(outfile1, Context)),
	io:format("FSM is terminating from reason: ~p\n", [Reason]).

code_change(_OldVsn, StateName, State, _Extra) ->
	io:format("TODO: code_change/4\n"),
	{ok, StateName, State}.

handle_event(Event, StateName, State) ->
	io:format("Received event ~p in state ~p, TODO: handle_event\n", [Event, StateName]),
	{stop, "terminate!", State}.

handle_info(Info, StateName, State) ->
	?MODULE:StateName(Info, State).

handle_sync_event(Event, _From, StateName, State) ->
	io:format("Received sync_event ~p in state ~p, TODO: handle_sync_event\n", [Event, StateName]),
	{stop, "terminate!", State}.


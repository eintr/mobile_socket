-module(socket_end).
-behaviour(gen_fsm).

-export([start_link/2]).
-export([init/1, handle_info/3, terminate/3]).
-export([wait_for_socket/2, wait_for_ok/2, relay/2]).

-import(config, [config/2]).
-import(log, [log/2, log/3]).

-include_lib("kernel/include/inet.hrl").

start_link(TrunkSocket, Config) ->
	gen_fsm:start_link(?MODULE, [TrunkSocket, Config], []).

init([TrunkSocket, Config]) ->
	% Maybe check config here?
	case config:get(socket_mode, Config) of
		server ->
			{ok, PrivKey} = mycrypt:load_privkey(config:get(server_key, Config)),
			{ok, CertBin} = mycrypt:load_x509(config:get(server_crt, Config)),
			ServerContext = Context++[{privkey, PrivKey}, {server_crt, CertBin}, {connect_time, 'TODO'}, {flowid, []}],
			log(log_info, "Socket-end server started with client ~p.", [inet:peernames(TrunkSocket)]),
			{next_state, wait_for_socket, {TrunkSocket, Config, ServerContext}};
		client ->
			{ok, CACertBin} = mycrypt:load_x509(config:get(ca_crt, Config));
			ClientContext = Context++[{ca_crt, CACertBin}, {flowid, []}],
			log(log_info, "Socket-end client started with server ~p", [inet:peernames(TrunkSocket)]),
			{next_state, wait_for_socket, {TrunkSocket, Config, ClientContext}};
		UnknownMode ->
			log(log_error, "Unknown socket_mode:~p", [UnknownMode]),
			{stop, "Unknown socket_mode", State}
	end.

wait_for_socket({socket_ready, TrunkSocket}, {TrunkSocket, Config, Context}=State) ->
	gen_tcp:controlling_process(TrunkSocket, self()),
	inet:setopts(TrunkSocket, [{active, true}, {packet, 2}, binary]),
	{next_state, relay, State};
wait_for_socket(_UnkownMsg, State) ->
	log(log_error, "UnkownMsg: ~p\n", [_UnkownMsg]),
	{stop, "UnkownMsg", State}.

wait_for_ok(goto, {TrunkSocket, Config, Statics}=Context) ->
	case gen_tcp:recv(TrunkSocket, 0) of
		{ok, Packet} ->
			case frame:decode(Packet, Statics)	of
				{ctl, trunk, ok, [SharedKey]} ->
					% Fine
					log(log_info, "trunker_ok, got shared key: ~p", [SharedKey]),
					{next_state, relay, {TrunkSocket, Config, config:set({sharedkey, SharedKey}, Statics)}};
				{ctl, trunk, failure, [Reason]} ->
					%log(log_error, "Peer failed."),
					{next_state, term, Context, 0};
				Msg ->
					log(log_error, "Got unknwon reply while expecting trunker_ok: ~p", [Msg]),
					{stop, normal, Context}
			end
	end.

relay({tcp_closed, TrunkSocket}, {TrunkSocket, Config, Statics}=Context) ->
	log(log_info, "Trunk socket closed, trunk_end terminate.", []),
	{next_state, term, Context};
relay({tcp, TrunkSocket, Frame}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:decode(Frame, Statics) of
		{data, FlowID, _CryptFlag, _Zip, RawData} ->
			case get(FlowID) of
				{Pid} ->
					log(log_debug, "Send ~p to ~p", [RawData, Pid]),
					Pid ! {flowdata, RawData};
				_ ->
					log(log_error, "Data flow ~p failed: No PID associated.", [FlowID])
			end,
			{next_state, relay, Context};
		{ctl, socket, cert_req, _} ->
			ok = send_cert(Context);
			{next_state, relay, Context};
		{ctl, socket, cert, Certificate} ->
			log(log_info, "Received peer certificate."),
            case public_key:pkix_verify(Certificate, config:get(ca_pubkey, Context)) of
                false ->
					log(log_error, "Server certificate verify failed."),
					{stop, "Server certificate verify failed."};
                true ->
                    log(log_info, "Server certificate verify Passed."),
					{next_state, relay, {TrunkSocket, Config, Statics++[{pub_key, mycrypt:extract_pubkey(Certificate)}, Context)}]}
            end;
		{ctl, socket, key_sync, {CRC32, SharedKey}} ->
			case erlang:crc32(SharedKey) of
				CRC32 ->
					log(log_info, "Shared key decrypted successfully! Accepted!"),
					{next_state, relay, {TrunkSocket, Config, Statics++[{sharedkey, SharedKey}]}};
				_ ->
					log(log_error, "Can't decrypt shared key! Reject!"),
					{ok, Frame} = frame:encode({ctl, socket, key_rej, {}}, Statics),
					gen_tcp:send(TrunkSocket, Frame),
					{next_state, relay, {TrunkSocket, Config, Statics}}
			end;
		{ctl, socket, key_rej, _} ->
		{ctl, pipeline, open, {FlowID, CryptFlag, Zip, MaxDelay, ReplyFlags, Data}=PipelineCFG} ->
			log(log_info, "~p: Creating flow_end for id ~p with CryptFlag=~p", [?MODULE, FlowID, CryptFlag]),
			{ok, Pid} = pipeline_end:start_link(self(), {{10,210,74,190}, 80}, PipelineCFG),
			put(FlowID, {Pid}),
			{next_state, relay, Context};
		{ctl, pipeline, close, {FlowID, CryptFlag, Zip}}=Msg ->
			case get(FlowID) of
				{Pid} ->
					Pid ! Msg,
					{next_state, relay, Context};
				_ ->
					log(log_error, "ctl_pipeline_close(~p) failed: No PID associated.", [FlowID]),
					{next_state, relay, Context}
			end;
		{ctl, Level, Code, Args} ->
			log(log_info, "Unknown control message: ~p/~p{~p}.", [Level, Code, Args]),
			{next_state, relay, Context};
		Msg ->
			log(log_info, "Unknown message: ~p.", [Msg]),
			{next_state, relay, Context}
	end;
relay({flowdata, FlowID, 1, Zip, RawData}, {TrunkSocket, Config, Statics}=Context) ->
	case config:get(sharedkey, Statics) of
		false ->
			log(log_error, "Got encrypt transfer request before shared key synced! Impossible!"),
			{Pid} = get(FlowID),
			Pid ! {exit, "Encryption dependence error"},
			{next_state, relay, Context};
		_ ->
			case frame:encode({data, FlowID, 1, Zip, RawData}, Statics) of
				{ok, Bin} ->
					gen_tcp:send(TrunkSocket, Bin),
					{next_state, relay, Context};
				{error, Reason} ->
					log(log_error, "frame:encode() failed: ~s, frame dropped.", [Reason]),
					{next_state, relay, Context}
			end
	end;
relay({flowdata, FlowID, 0, Zip, RawData}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:encode({data, FlowID, 0, Zip, RawData}, Statics) of
		{ok, Bin} ->
			gen_tcp:send(TrunkSocket, Bin),
			{next_state, relay, Context};
		{error, Reason} ->
			log(log_error, "frame:encode() failed: ~s, frame dropped.", [Reason]),
			{next_state, relay, Context}
	end;
relay({flowctl, Code, Args}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:encode({ctl, pipeline, Code, Args}, Statics) of
		{ok, Bin} ->
			log(log_info, "Sending ~p into trunk_socket.", [{ctl, pipeline, Code, Args}]),
			ok = gen_tcp:send(TrunkSocket, Bin),
			{next_state, relay, Context};
		{error, Reason} ->
			log(log_error, "frame:encode() failed: ~s, frame dropped.", [Reason]),
			{next_state, relay, Context}
	end;
relay({flowend_exit, FlowId}, Context) ->
	erase(FlowId),
	{next_state, relay, Context};
relay(_Msg, Context) ->
	log(log_error, "Trunk_end ignored unknown message: ~p", [_Msg]),
	{next_state, relay, Context}.

terminate(Reason, _StateName, {TrunkSocket, _Config, _Statics}) ->
    gen_tcp:close(TrunkSocket),
    io:format("Trunc_end is terminating from reason: ~p\n", [Reason]).

handle_info({'EXIT', FromPID, Reason}, StateName, {TrunkSocket, Config, Statics}=Context) ->
	log(log_info, "trunk_end: Detected flow_end ~p exited.", [FromPID]),
	{next_state, StateName, Context};
handle_info(Info, StateName, Context) ->
	?MODULE:StateName(Info, Context).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

send_cert({TrunkSocket, Config, Context}=State) ->
	CertBin = config:get(server_crt, Context),
	{ok, Frame} = frame:encode({ctl, socket, cert, {erlang:crc32(CertBin), CertBin}}, Context),
	gen_tcp:send(TrunkSocket, Frame).

context(K, C) ->
	config:get(K, C).


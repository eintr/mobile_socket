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
	{ok, wait_for_socket, {TrunkSocket, Config, [{flowid, []}]}}.

wait_for_socket({socket_ready, TrunkSocket}, {TrunkSocket, Config, Context}=State) ->
	gen_tcp:controlling_process(TrunkSocket, self()),
	inet:setopts(TrunkSocket, [{active, true}, {packet, 2}, binary]),
	log(log_info, "Serving client: ~p\n", [inet:peernames(TrunkSocket)]),
	{next_state, relay, {TrunkSocket, Config, config:set({connect_time, 'TODO'}, Context)}};
wait_for_socket(_UnkownMsg, State) ->
	io:format("UnkownMsg: ~p\n", [_UnkownMsg]),
	{next_state, wait_for_socket, State}.

send_cert({TrunkSocket, Config, Context}=State) ->
	{ok, PrivKey} = mycrypt:load_privkey("key/test.key"),
	{ok, CertBin} = mycrypt:load_x509("key/test.crt"),
	{ok, Frame} = frame:encode({ctl, socket, cert, {erlang:crc32(CertBin), CertBin}}, Context),
	ok = gen_tcp:send(TrunkSocket, Frame),
	{TrunkSocket, Config, Context++[{privkey, PrivKey}]}.

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
			{next_state, relay, send_cert(Context)};
		{ctl, socket, key_sync, {CRC32, SharedKey}} ->
			case erlang:crc32(SharedKey) of
				CRC32 ->
					{next_state, relay, {TrunkSocket, Config, Statics++[{sharedkey, SharedKey}]}};
				_ ->
					log(log_error, "Can't decrypt shared key! Rejected!"),
					{ok, Frame} = frame:encode({ctl, socket, key_rej, {}}, Statics),
					gen_tcp:send(TrunkSocket, Frame),
					{next_state, relay, {TrunkSocket, Config, Statics}}
			end;
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

context(K, C) ->
	config:get(K, C).


-module(trunk_end).
-behaviour(gen_fsm).

-export([start_link/2]).
-export([init/1, handle_info/3, terminate/3]).
-export([wait_for_socket/2, send_config/2, wait_for_ok/2, relay/2, term/2]).

-import(config, [config/2]).
-import(log, [log/2, log/3]).

-include_lib("kernel/include/inet.hrl").

start_link(TrunkSocket, Config) ->
	gen_fsm:start_link(?MODULE, [TrunkSocket, Config], []).

init([TrunkSocket, Config]) ->
	{ok, wait_for_socket, {TrunkSocket, Config, [{flowid, []}]}}.

wait_for_socket({socket_ready, TrunkSocket}, {TrunkSocket, Config, Context}=State) ->
	gen_tcp:controlling_process(TrunkSocket, self()),
	inet:setopts(TrunkSocket, [{active, false}, {packet, 2}, binary]),
	io:format("Serving client: ~p\n", [inet:peernames(TrunkSocket)]),
	send_config(goto, {TrunkSocket, Config, config:set({connect_time, 'TODO'}, Context)});
wait_for_socket(_UnkownMsg, State) ->
	io:format("UnkownMsg: ~p\n", [_UnkownMsg]),
	{next_state, wait_for_socket, State}.

send_config(goto, {TrunkSocket, Config, Context}=State) ->
	{ok, PrivKey} = mycrypt:load_privkey("key/test.key"),
	{ok, CertBin} = mycrypt:load_x509("key/test.crt"),
	{ok, Frame} = frame:encode({ctl, trunk, config, [CertBin]}, Context),
	ok = gen_tcp:send(TrunkSocket, Frame),
	wait_for_ok(goto, {TrunkSocket, Config, Context++[{privkey, PrivKey}]});
send_config(_UnkownMsg, Context) ->
	io:format("UnkownMsg: ~p\n", [_UnkownMsg]),
	{next_state, term, Context, 0}.

wait_for_ok(goto, {TrunkSocket, Config, Statics}=Context) ->
	case gen_tcp:recv(TrunkSocket, 0) of
		{ok, Packet} ->
			case frame:decode(Packet, Statics)	of
				{ctl, trunk, ok, [SharedKey]} ->
					% Fine
					log(log_info, "trunker_ok, got shared key: ~p", [SharedKey]),
					ok = inet:setopts(TrunkSocket, [{active, true}]),
					{next_state, relay, {TrunkSocket, Config, config:set({sharedkey, SharedKey}, Statics)}};
				{ctl, trunk, failure, [Reason]} ->
					%log(log_error, "Peer failed."),
					{next_state, term, Context, 0};
				Msg ->
					log(log_error, "Got unknwon reply while expecting trunker_ok: ~p", [Msg]),
					term(goto, Context)
			end
	end.

relay({tcp_closed, TrunkSocket}, {TrunkSocket, Config, Statics}=Context) ->
	log(log_info, "Trunk socket closed, trunk_end terminate.", []),
	{next_state, term, Context};
relay({tcp, TrunkSocket, Frame}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:decode(Frame, Statics) of
		{data, FlowID, CryptFlag, RawData} ->
			case get(FlowID) of
				{Pid} ->
					log(log_debug, "Send ~p to ~p", [RawData, Pid]),
					Pid ! {flowdata, RawData};
				_ ->
					log(log_error, "Data to flow ~p failed: No PID associated.", [FlowID])
			end,
			{next_state, relay, Context};
		{ctl, flow, open, [FlowID, CryptFlag, RequestData]} ->
			log(log_info, "~p: Creating flow_end for id ~p with CryptFlag=~p", [?MODULE, FlowID, CryptFlag]),
			{ok, Pid} = flow_end:start_link(self(), {{10,210,74,190}, 80}, FlowID, CryptFlag, RequestData),
			put(FlowID, {Pid}),
			{next_state, relay, Context};
		{ctl, flow, close, [FlowID, CryptFlag]}=Msg ->
			case get(FlowID) of
				{Pid} ->
					Pid ! Msg,
					{next_state, relay, Context};
				_ ->
					log(log_error, "ctl_flow_close(~p) failed: No PID associated.", [FlowID]),
					{next_state, relay, Context}
			end;
		{ctl, Level, Code, Args} ->
			log(log_info, "Unknown control message: ~p/~p(~p).", [Level, Code, Args]),
			{next_state, relay, Context};
		Msg ->
			log(log_info, "Unknown message: ~p.", [Msg]),
			{next_state, relay, Context}
	end;
relay({flowdata, FlowID, CryptFlag, RawData}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:encode({data, FlowID, CryptFlag, RawData}, Statics) of
		{ok, Bin} ->
			gen_tcp:send(TrunkSocket, Bin),
			{next_state, relay, Context};
		{error, Reason} ->
			log(log_error, "frame:encode() failed: ~s, frame dropped.", [Reason]),
			{next_state, relay, Context}
	end;
relay({flowctl, Level, Code, Args}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:encode({ctl, Level, Code, Args}, Statics) of
		{ok, Bin} ->
			log(log_error, "Sending ~p into trunk_socket.", [{ctl, Level, Code, Args}]),
			gen_tcp:send(TrunkSocket, Bin),
			{next_state, relay, Context};
		{error, Reason} ->
			log(log_error, "frame:encode() failed: ~s, frame dropped.", [Reason]),
			{next_state, relay, Context}
	end;
relay({get_flowid, From}, Context) ->
	IDList = config:get(flowid, Context),
	case alloc_flowid(IDList) of
		full ->
			From ! full,
			{next_state, relay, Context};
		Id ->
			From ! Id,
			{next_state, relay, config:set({flowid, IDList++[Id]}, Context)}
	end;
relay({flowend_exit, FlowId}, Context) ->
	erase(FlowId),
	{next_state, relay, Context};
relay(_Msg, Context) ->
	log(log_error, "Trunk_end ignored unknown message: ~p", [_Msg]),
	{next_state, relay, Context}.

term(goto, State) ->
	{stop, "Normal terminate", State}.

terminate(Reason, _StateName, {TrunkSocket, _Config, _Statics}) ->
    gen_tcp:close(TrunkSocket),
    io:format("Trunc_end is terminating from reason: ~p\n", [Reason]).

handle_info(Info, StateName, State) ->
	?MODULE:StateName(Info, State).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

alloc_flowid(List) ->
	NextID=lists:max(List)+1,
	if
		NextID==1 bsl 31 ->
			SlowID=uniqid_slow(List),
			SlowID;
		true ->
			NextID
	end.

uniqid_slow(List) when length(List)==1 bsl 31 -1 ->
	full;
uniqid_slow(List) ->
	uniqid_slow(0, List).
uniqid_slow(Id, List) ->
	case lists:member(Id, List) of
		true -> uniqid_slow(Id+1, List);
		fasle -> Id
	end.


%%%%%%%%%%%%%%%%%%%%%%%%%%

context(K, C) ->
	config:get(K, C).


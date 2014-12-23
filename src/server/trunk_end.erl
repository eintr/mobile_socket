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
	send_config(goto, {TrunkSocket, Config, config:set(	{connect_time, 'TODO'}, Context++[{pubkey, <<"Fake pubkey">>}, {privkey, <<"Fake privkey">>}])});
wait_for_socket(_UnkownMsg, State) ->
	io:format("UnkownMsg: ~p\n", [_UnkownMsg]),
	{next_state, wait_for_socket, State}.

send_config(goto, {TrunkSocket, Config, Context}=State) ->
	{ok, Frame} = frame:encode({ctl, trunk, config, [<<"====[Fake certificate]====", 0:8>>] }, Context),
	ok = gen_tcp:send(TrunkSocket, Frame),
	wait_for_ok(goto, State);
send_config(_UnkownMsg, Context) ->
	io:format("UnkownMsg: ~p\n", [_UnkownMsg]),
	{next_state, term, Context, 0}.

wait_for_ok(goto, {TrunkSocket, Config, Statics}=Context) ->
	case gen_tcp:recv(TrunkSocket, 0) of
		{ok, Packet} ->
			case frame:decode(Packet, [])	of
				{ctl, trunk, ok, [SharedKey]} ->
					% Fine
					log(log_info, "trunker_ok, got shared key: ~p", [SharedKey]),
					ok = inet:setopts(TrunkSocket, [{active, true}]),
					{next_state, relay, Context};
				{ctl, trunk, failure, [Reason]} ->
					%log(log_error, "Peer failed."),
					{next_state, term, Context, 0};
				Msg ->
					log(log_error, "Got unknwon reply while expecting trunker_ok: ~p", [Msg]),
					term(goto, Context)
			end
	end.

relay({tcp_closed, TrunkSocket}, {TrunkSocket, Config, Statics}=Context) ->
	log(log_info, "Trunk socket to ~p:~p closed, trunk_end terminate.", []),
	{next_state, term, Context};
relay({tcp, TrunkSocket, Frame}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:decode(Frame, Statics) of
		{data, FlowID, RawData} ->
			case get(FlowID) of
				{Pid, _RequestData} ->
					Pid ! {data, RawData};
				_ ->
					log(log_error, "Data to flow ~p failed: No PID associated.", [FlowID])
			end,
			{next_state, relay, Context};
		{ctl, flow, open, [FlowID, RequestData]} ->
			{ok, Pid} = flow_end:start_link(context(trunker_hub, Statics), {{10,210,74,190}, 80}, FlowID),
			put(FlowID, {Pid, RequestData}),
			{next_state, relay, Context};
		{ctl, flow, close, [FlowID]}=Msg ->
			case get(FlowID) of
				{Pid, _RequestData} ->
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
	case frame:encode({data, FlowID, RawData}, context(sharedkey, Context)) of
		{ok, Bin} ->
			gen_tcp:send(TrunkSocket, Bin),
			{next_state, relay, Context};
		{error, Reason} ->
			log(log_error, "frame:encode() failed: ~s, frame dropped.", [Reason]),
			{next_state, relay, Context}
	end;
relay({flowctl, Level, Code, Args}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:encode({ctl, Level, Code, Args}, context(sharedkey, Context)) of
		{ok, Bin} ->
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

trunker_hub(Client_socket, Config, Context) ->
	trunker_hub_loop(Client_socket, Config, padding_of_PrioQueue, Context).

trunker_hub_loop(Client_socket, _Config, _PrioQueue, Context) ->
	receive
		{ctl, Level, Code, Args} ->
			case frame:encode({ctl, Level, Code, Args}, context(sharedkey, Context)) of
				{ok, Bin} ->
					gen_tcp:send(Client_socket, Bin);
				{error, Reason} ->
					log(log_error, "frame:encode() failed: ~s", [Reason])
			end;
		Msg ->
			log(log_error, "trunker received unknown message: ~p", [Msg])
	end.

context(K, C) ->
	config:get(K, C).


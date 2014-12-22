-module(client).
-behaviour(gen_fsm).

-export([run/0, start_link/2]).
-export([init/1, code_change/4, handle_event/3, handle_info/3, handle_sync_event/4, terminate/3]).
-export([prepare/2, recv_config/2, trunk_ok/2, create_flow/2, main_loop/2, term/2]).

-include_lib("kernel/include/inet.hrl").


run() ->
	{ok, Pid} = start_link({{127,0,0,1}, 18080}, []),
	gen_fsm:send_event(Pid, go),
	loop(Pid).

loop(Pid) ->
	receive
		_ -> loop(Pid)
	end.

start_link({IP, Port}, Config) ->
	gen_fsm:start_link(?MODULE, [{IP, Port}, Config], []).

init([{IP, Port}, Config]) ->
	{ok, Socket} = gen_tcp:connect(IP, Port, [binary, {packet, 2}, {active, false}]),
	io:format("Connected to ~p:~p\n", [IP, Port]),
	{ok, prepare, {Socket, Config, []}}.

prepare(go, {TrunkSocket, Config, _Context}=_State) ->
	inet:setopts(TrunkSocket, [{active, true}]),
	{next_state, recv_config, {TrunkSocket, Config, [{flowtable, []}]}, infinity}.

recv_config({tcp, TrunkSocket, Frame}, {TrunkSocket, Config, Context}=_State) ->
	case frame:decode(Frame, Context) of
		{ctl, trunk, config, Certificate} ->
			% Extract pub_key from Certificate
			io:format("recv_config: Certificate is:~p\n", [Certificate]),
			trunk_ok(goto, {TrunkSocket, Config, config:set({pub_key, <<"PubKey">>}, Context)});
		Msg ->
			io:format("Got a ~p while expecting {ctl, trunk, config}\n", [Msg])
	end;
recv_config(_UnkownMsg, State) ->
	io:format("UnkownMsg: ~p\n", [_UnkownMsg]),
	term(goto, State).

trunk_ok(goto, {TrunkSocket, Config, Context}=_State) ->
	Shared_key = <<"RandomSharedKey">>,
	Encrypted_shared_key = mycrypt:encrypt_shared_key(Shared_key, config:get(pub_key, Context)),
	{ok, Bin} = frame:encode({ctl, trunk, ok, [Encrypted_shared_key]}, Context),
	ok = gen_tcp:send(TrunkSocket, Bin),
	create_flow(goto, {TrunkSocket, Config, config:set({sharedkey, Shared_key}, Context)}).

create_flow(goto, {TrunkSocket, _Config, Context}=State) ->
	{ok, Bin} = frame:encode({ctl, flow, open, [1, <<"HTTP Header things...">>]}, Context),
	ok = gen_tcp:send(TrunkSocket, Bin),
	{next_state, main_loop, State, 5000}.

main_loop(timeout, State) ->
	io:format("Did not get any data in 5 secends, continue...\n"),
	{next_state, main_loop, State, 5000};
main_loop({tcp_closed, TrunkSocket}, {TrunkSocket, _Config, _Context}=State) ->
	io:format("Socket closed by peer.\n"),
	{next_state, term, State};
main_loop({tcp, TrunkSocket, Frame}, {TrunkSocket, _Config, Context}=State) ->
	case frame:decode(Frame, Context) of
		{data, 1, Data} ->
			io:format("Got data: ~p\n", [Data]),
			{next_state, main_loop, State, 5000};
		{data, Flowid, Data} ->
			io:format("?? Got data in incorrect flowid(~p): ~p\n", [Flowid, Data]),
			{next_state, main_loop, State, 5000};
		{ctl, trunk, failure, [ErrorMsg]} ->
			io:format("?? Trunk failed:~p\n", [ErrorMsg]),
			term(goto, State);
		{ctl, flow, close, [1]} ->
			io:format("Flow closed normally.\n"),
			term(goto, State);
		{ctl, flow, failure, [FlowID, ErrorMsg]} ->
			io:format("Flow ~p closed abnormally: ~p\n", [FlowID, ErrorMsg]),
			term(goto, State);
		_Msg ->
			io:format("Unknown Message:~p\n", [_Msg]),
			{next_state, main_loop, State, 5000}
	end.

term(goto, State) ->
	{stop, "terminate!", State}.

terminate(Reason, _StateName, {TrunkSocket, _Config, _Context}=_State) ->
	gen_tcp:close(TrunkSocket),
	io:format("FSM is terminating from reason: ~p\n", [Reason]).

code_change(_OldVsn, StateName, State, _Extra) ->
	io:format("TODO: code_change/4\n"),
	{ok, StateName, State}.

handle_event(Event, StateName, State) ->
	io:format("Received event ~p in state ~p, TODO: handle_event\n", [Event, StateName]),
	{stop, "terminate!", State}.

handle_info(Info, StateName, State) ->
	io:format("Received info ~p in state ~p\n", [Info, StateName]),
	?MODULE:StateName(Info, State).

handle_sync_event(Event, _From, StateName, State) ->
	io:format("Received sync_event ~p in state ~p, TODO: handle_sync_event\n", [Event, StateName]),
	{stop, "terminate!", State}.


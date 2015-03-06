-module(client_socket_end).
-behaviour(gen_fsm).

-export([start_link/1]).
-export([init/1, handle/2, terminate/3, handle_info/3]).

-include_lib("kernel/include/inet.hrl").

start_link(Config) ->
	gen_fsm:start_link(?MODULE, [Config++[{pipelineid, 1}]], []).

init([Config]) ->
	{ok, Socket} = gen_tcp:connect(kv:get(server_addr, Config), kv:get(server_port, Config), [binary, {active, true}, {packet, 2}]),
	{ok, handle, {Socket, Config, []}}.

handle_info(Info, StateName, State) ->
	?MODULE:StateName(Info, State).

terminate(Reason, StateName, StateData) ->
	io:format("terminate at state ~p.", [StateName]).

handle({From, enum}, {Socket, Config, Statics}=Context) ->
	From ! Context,
	{next_state, handle, Context};

handle({From, terminate}, {Socket, Config, Statics}=Context) ->
	{stop, Context, "Demanded termination."};

handle({From, data, FlowID, CryptFlag, Zipflag, RawData}, {Socket, Config, Statics}=Context) ->
	io:format("~p: Got data from pipeline_end: ~p\n", [?MODULE, RawData]),
	case frame:encode({data, FlowID, 0, 0, RawData}, Config) of
		{ok, Bin} ->
			ok = gen_tcp:send(Socket, Bin),
			io:format("~p: Data sent\n", [?MODULE]),
			{next_state, handle, Context};
		{error, Reason} ->
			io:format("log_error: frame:encode() failed: ~s, frame dropped.", [Reason]),
			{next_state, handle, Context}
	end;

handle({From, ctl, pipeline, open, {FlowID, CryptFlag, Zip,  MaxDelay, ReplyFlags, Data}}, {Socket, Config, Statics}=Context) ->
	io:format("~p: Got ctl/pipeline/open from pipeline_end.\n", [?MODULE]),
	{ok, BinData} = frame:encode({ctl, pipeline, open, {FlowID, CryptFlag, Zip, MaxDelay, ReplyFlags, Data}}, Config),
	ok = gen_tcp:send(Socket, BinData),
	put(FlowID, {From, 0, 0}),
	From ! ok,
	{next_state, handle, Context};

handle({From, ctl, pipeline, close, {FlowID, CryptFlag, Zip}}, {Socket, Config, Statics}=Context) ->
	{ok, BinData} = frame:encode({ctl, pipeline, close, {FlowID, CryptFlag, Zip}}, Config),
	ok = gen_tcp:send(Socket, BinData),
	erase(FlowID),
	%From ! ok,
	{next_state, handle, Context};

handle({From, ctl, Level, Code, Args}, {Socket, Config, Statics}=Context) ->
	case frame:encode({ctl, Level, Code, Args}, kv:get(sharedkey, Context)) of
		{ok, Bin} ->
			gen_tcp:send(Socket, Bin),
			{next_state, handle, Context};
		{error, Reason} ->
			io:format("log_error: frame:encode() failed: ~s, frame dropped.", [Reason]),
			{next_state, handle, Context}
	end;

handle({From, get_pipelineid}, {Socket, Config, Statics}=Context) ->
	ID = kv:get(pipelineid, Config),
	case get(ID) of
		{_From, _, _} ->
			NewConfig = kv:set(pipelineid, ID+1, Config),
			handle({From, get_pipelineid}, {Socket, NewConfig, Statics});
		undefined ->
			From ! {id, ID},
			NewConfig = kv:set(pipelineid, ID+1, Config),
			{next_state, handle, {Socket, NewConfig, Statics}}
	end;

handle({tcp, Socket, Data}, {Socket, Config, Statics}=Context) ->
	case frame:decode(Data, [])	of
		{data, FlowID, Encrypt, Zip, RawData} ->
			case get(FlowID) of
				{Pid, _Prio, _RequestData} ->
					Pid ! {data, RawData};
				_ ->
					io:format("log_error: Data to flow ~p failed: No PID associated.", [FlowID])
			end,
			{next_state, handle, Context};
		{ctl, pipeline, close, {FlowID}}=Msg ->
			case get(FlowID) of
				{Pid, _Prio, _RequestData} ->
					Pid ! {ctl, pipeline, close},
					erase(FlowID),
					{next_state, handle, Context};
				_ ->
					io:format("log_error: ctl_framer_close(~p) failed: No PID associated.", [FlowID]),
					{next_state, handle, Context}
			end;
		{ctl, pipeline, failure, {FlowID}}=Msg ->
			case get(FlowID) of
				{Pid, _Prio, _RequestData} ->
					Pid ! {ctl, pipeline, failure},
					erase(FlowID),
					{next_state, handle, Context};
				_ ->
					io:format("log_error: ctl_framer_close(~p) failed: No PID associated.", [FlowID]),
					{next_state, handle, Context}
			end;
		{ctl, socket, cert, [Cert]} ->
			io:format("{ctl, socket, cert} not implemented, yet.\n"),
			{next_state, handle, Context};
		{ctl, Level, Code, Args} ->
			io:format("log_info: Unknown control message: ~p/~p(~p).", [Level, Code, Args]),
			{next_state, handle, Context};
		Msg ->
			io:format("log_info: Unknown message: ~p.", [Msg]),
			{next_state, handle, Context}
	end;

handle({tcp_closed, Socket}, {Socket, Config, Statics}=Context) ->
	{stop, Context, "Peer closed"}.
	

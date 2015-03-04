-module(client_trunk_end).
-behaviour(gen_fsm).

-export([start_link/2]).
-export([init/1]).

-include_lib("kernel/include/inet.hrl").

start_link(TrunkSocket, Config) ->
	gen_fsm:start_link(?MODULE, [TrunkSocket, Config++[{pipelineid, 1}]], []).

init([TrunkSocket, Config]) ->
	% set TrunkSocket active
	{ok, handle, {TrunkSocket, Config, []}}.

handle_info(Info, StateName, State) ->
	?MODULE:StateName(Info, State).

handle({From, data, FlowID, CryptFlag, RawData}, {TrunkSocket, Config, Statics}) ->
	case frame:encode({data, Prio, FlowID, RawData}, context(sharedkey, Context)) of
		{ok, Bin} ->
			gen_tcp:send(TrunkSocket, Bin),
			{next_state, handle, Context};
		{error, Reason} ->
			log(log_error, "frame:encode() failed: ~s, frame dropped.", [Reason]),
			{next_state, handle, Context}
	end;

handle({From, ctl, pipeline, open, {FlowID, CryptFlag, Zip,  MaxDelay, ReplyFlags, Data}}, {TrunkSocket, Config, Statics}=Context) ->
	{ok, BinData} = frame:encode({ctl, pipeline, open, {FlowID, CryptFlag, Zip, MaxDelay, ReplyFlags, Data}}, Config),
	ok = gen_tcp:send(TrunkSocket, BinData),
	put(FlowID, {From, 0, 0}),
	From ! ok,
	{next_state, handle, Context};

handle({From, ctl, pipeline, close, {FlowID, CryptFlag, Zip}}, {TrunkSocket, Config, Statics}=Context) ->
	{ok, BinData} = frame:encode({ctl, pipeline, close, {FlowID, CryptFlag, Zip}}, Config),
	ok = gen_tcp:send(TrunkSocket, BinData),
	erase(FlowID),
	From ! ok,
	{next_state, handle, Context};

handle({From, ctl, Level, Code, Args}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:encode({ctl, Level, Code, Args}, context(sharedkey, Context)) of
		{ok, Bin} ->
			gen_tcp:send(TrunkSocket, Bin),
			{next_state, handle, Context};
		{error, Reason} ->
			log(log_error, "frame:encode() failed: ~s, frame dropped.", [Reason]),
			{next_state, handle, Context}
	end;

handle({From, get_pipelineid}, {TrunkSocket, Config, Statics}=Context) ->
	ID = config:get(pipelineid, Config),
	case get(ID) of
		{_From, _, _} ->
			NewConfig = config:set(pipelineid, ID+1, Config),
			handle({From, get_pipelineid}, {TrunkSocket, NewConfig, Statics});
		undefined ->
			From ! {id, ID},
			NewConfig = config:set(pipelineid, ID+1, Config),
			{next_state, handle, {TrunkSocket, NewConfig, Statics}}
	end;

handle({tcp, TrunkSocket, Data}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:decode(Data, [])	of
		{data, FlowID, Encrypt, Zip, RawData} ->
			case get(FlowID) of
				{Pid, _Prio, _RequestData} ->
					Pid ! {data, Encrypt, Zip, RawData};
				_ ->
					log(log_error, "Data to flow ~p failed: No PID associated.", [FlowID])
			end,
			{next_state, handle, Context};
		{ctl, pipeline, close, {FlowID}}=Msg ->
			case get(FlowID) of
				{Pid, _Prio, _RequestData} ->
					Pid ! Msg,
					erase(FlowID),
					{next_state, handle, Context};
				_ ->
					log(log_error, "ctl_framer_close(~p) failed: No PID associated.", [FlowID]),
					{next_state, handle, Context}
			end;
		{ctl, pipeline, failure, {FlowID}}=Msg ->
			case get(FlowID) of
				{Pid, _Prio, _RequestData} ->
					Pid ! Msg,
					erase(FlowID),
					{next_state, handle, Context};
				_ ->
					log(log_error, "ctl_framer_close(~p) failed: No PID associated.", [FlowID]),
					{next_state, handle, Context}
			end;
		{ctl, socket, cert, [Cert]} ->
			io:format("{ctl, socket, cert} not implemented, yet.\n"),
			{next_state, handle, Context};
		{ctl, Level, Code, Args} ->
			log(log_info, "Unknown control message: ~p/~p(~p).", [Level, Code, Args]),
			{next_state, handle, Context};
		Msg ->
			log(log_info, "Unknown message: ~p.", [Msg]),
			{next_state, handle, Context}
	end;

handle({tcp_close, TrunkSocket}, {TrunkSocket, Config, Statics}=Context) ->
	{stop, Context, "Peer closed"}.
	
alloc_flowid(List) ->

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
	%PrioQueue = prioqueue:new(8),
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
	config:config(K, C).


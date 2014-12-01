-module(trunk_end).
-behaviour(gen_fsm).

-export([start_link/0, start_link/1]).
-export([init/2]).

-import(config, [config/2]).
-import(log, [log/2, log/3]).

-include_lib("kernel/include/inet.hrl").

start_link(TrunkSocket, Config) ->
	gen_fsm:start_link(?MODULE, [TrunkSocket, Config], []).

init([TrunkSocket, Config]) ->
	{ok, wait_for_socket, {TrunkSocket, Config, []}}.

wait_for_socket({socket_ready, TrunkSocket}, {TrunkSocket, Config, Statics}=Context) ->
	inet:setopts(TrunkSocket, [{active, false}, {packet, 2}, binary]),
	io:format("Serving client: ~p\n", [inet:peernames(TrunkSocket)]),
    {next_state, send_config, {TrunkSocket, Config, Statics++[{connect_time, 'TODO'}]}, 0};
wait_for_socket(_UnkownMsg, Context) ->
	io:format("UnkownMsg: ~p\n", [_UnkownMsg]),
	{next_state, wait_for_socket, Context}.

send_config(timeout, {TrunkSocket, Config, Statics}=Context) ->
	{ok, Frame} = frame:encode({ctl, trunk, config, <<"====[Fake certificate]====">> }, Context),
	gen_tcp:send(TrunkSocket, Frame),
	{next_state, wait_for_ok, Context};
send_config(_UnkownMsg, Context) ->
	io:format("UnkownMsg: ~p\n", [_UnkownMsg]),
	{next_state, term, Context, 0}.

wait_for_ok(timeout, {TrunkSocket, Config, Statics}=Context) ->
	case gen_tcp:recv(TrunkSocket, 0) of
		{ok, Packet} ->
			case frame:decode(Packet, [])	of
				{ctl, trunk, ok, [SharedKey]} ->
					% Fine
					log(log_debug, "trunker_ok, got shared key: ~p", [SharedKey]),
					inet:setopts(TrunkSocket, [{active, true}]),
					{nextstate, relay, {TrunkSocket, Config, Statics}, 60000};
				{ctl, trunk, failure, [Reason]} ->
					%log(log_error, "Peer failed."),
					{nextstate, term, Context, 0};
				Msg ->
					log(log_error, "Got unknwon reply while expecting trunker_ok: ~p", [Msg]),
					{nextstate, term, Context, 0};
			end
	end.

relay(timeout, {TrunkSocket, Config, Statics}=Context) ->
relay({tcp, TrunkSocket, Frame}, {TrunkSocket, Config, Statics}=Context) ->
	case frame:decode(Frame, Context) of
		{data, _Prio, FlowID, RawData} ->
			case get(FlowID) of
				{Pid, _Prio, _RequestData} ->
					Pid ! {data, RawData};
				_ ->
					log(log_error, "Data to flow ~p failed: No PID associated.", [FlowID])
			end,
			{nextstate, relay, Context};
		{ctl, framer, open, [Prio, FlowID, RequestData]} ->
			Pid = framer:create(context(trunker_hub, Context), Prio, FlowID, RequestData),
			put(FlowID, {Pid, Prio, RequestData}),
			{nextstate, relay, Context};
		{ctl, framer, close, [FlowID]}=Msg ->
			case get(FlowID) of
				{Pid, _Prio, _RequestData} ->
					Pid ! Msg,
					{nextstate, relay, Context};
				_ ->
					log(log_error, "ctl_framer_close(~p) failed: No PID associated.", [FlowID]),
					{nextstate, relay, Context};
			end;
		{ctl, Level, Code, Args} ->
			log(log_info, "Unknown control message: ~p/~p(~p).", [Level, Code, Args]),
			{nextstate, relay, Context};
		Msg ->
			log(log_info, "Unknown message: ~p.", [Msg]),
			{nextstate, relay, Context};
	end;
relay({flowdata, _Prio, FlowID, CryptFlag, RawData}, Context) ->



%%%%%%%%%%%%%%%%%%%%%%%%%%

protocol(send_config, Client_socket, Config, Context) ->
	io:format("send_config\n"),
	% Read certificate and server key here.
	protocol(recv_trunker_ack, Client_socket, Config, Context++[{pubkey, <<"Fake pubkey">>}, {privkey, <<"Fake privkey">>}]);

protocol(main_loop, Client_socket, Config, Context) ->
	case gen_tcp:recv(Client_socket, 0) of
		{ok, Packet} ->
			case frame:decode(Packet, Context) of
				{data, _Prio, FlowID, RawData} ->
					case get(FlowID) of
						{Pid, _Prio, _RequestData} ->
							Pid ! {data, RawData};
						_ ->
							log(log_error, "Data to flow ~p failed: No PID associated.", [FlowID])
					end,
					protocol(main_loop, Client_socket, Config, Context);
				{ctl, framer, open, [Prio, FlowID, RequestData]} ->
					Pid = framer:create(context(trunker_hub, Context), Prio, FlowID, RequestData),
					put(FlowID, {Pid, Prio, RequestData}),
					protocol(main_loop, Client_socket, Config, Context);
				{ctl, framer, close, [FlowID]}=Msg ->
					case get(FlowID) of
						{Pid, _Prio, _RequestData} ->
							Pid ! Msg,
							protocol(main_loop, Client_socket, Config, Context);
						_ ->
							log(log_error, "ctl_framer_close(~p) failed: No PID associated.", [FlowID]),
							protocol(main_loop, Client_socket, Config, Context)
					end;
				{ctl, Level, Code, Args} ->
					log(log_info, "Unknown control message: ~p_~p(~p).", [Level, Code, Args]),
					protocol(main_loop, Client_socket, Config, Context);
				Msg ->
					log(log_info, "Unknown message: ~p.", [Msg]),
					protocol(main_loop, Client_socket, Config, Context)
			end
	end;

protocol(name_resolv, Client_socket, Config, Context) ->
	case inet_res:gethostbyname(config(domainname, Context)) of
		{ok, Hostent} ->
			[Daddr|_] = Hostent#hostent.h_addr_list,
			protocol(try_connect, Client_socket, Config, Context++[{daddr, Daddr}]);
		{error, Reason} ->
			protocol(term, Client_socket, Config, Context++[{error, Reason}])
	end;

protocol(term, _Client_socket, _Config, _Context) ->
	%io:format("terminating\n"),
	% TODO: Do some log if needed.
	ok.


trunker_hub(Client_socket, Config, Context) ->
	%PrioQueue = prioqueue:new(8),
	trunker_hub_loop(Client_socket, Config, padding_of_PrioQueue, Context).

trunker_hub_loop(Client_socket, _Config, _PrioQueue, Context) ->
	receive
		{data, FlowID, Prio, RawData} ->
			case frame:encode({data, Prio, FlowID, RawData}, context(sharedkey, Context)) of
				{ok, Bin} ->
					gen_tcp:send(Client_socket, Bin);
				{error, Reason} ->
					log(log_error, "frame:encode() failed: ~s", [Reason])
			end;
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


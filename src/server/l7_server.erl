-module(l7_server).
-behaviour(gen_server).

-export([start_link/2]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2, code_change/3]).

start_link(SockAddr, L7Name, L7Config) ->
	io:format("~p:start_link(~p, ~p)\n", [?MODULE, SockAddr, config:set({l7name, L7Name},L7Config)]),
	gen_server:start_link(?MODULE, [SockAddr, L7Config], []).

init([{Addr, Port}, L7Config]) ->
    io:format("Try to Listen: {~p, ~b}\n", [Addr, Port]),
	case gen_tcp:listen(Port, [binary, {ip, Addr}, {packet, 0}, {reuseaddr, true}, {keepalive, true}, {backlog, 30}, {active, false}]) of
		{ok, ListenSocket} ->
			io:format("gen_tcp:listen(): OK\n"),
			{ok, Ref} = prim_inet:async_accept(ListenSocket, -1),
			io:format("prim_inet:async_accept()=~p, OK\n", [Ref]),
			{ok, {ListenSocket, Ref, L7Config, []}};
		{error, Reason} -> {stop, Reason}
	end.

handle_info({'EXIT', TrunkPid, Reason}, {ListenSocket, Ref, Config, Context}=_State) ->
	{noreply, {ListenSocket, Ref, Config, lists:keydelete(TrunkPid, 2, Context)}};
handle_info({inet_async, ListenSocket, Ref, {ok, TrunkSocket}}, {ListenSocket, Ref, Config, Context}=_State) ->
	io:format("Got connection from: ~p\n", [inet:peernames(TrunkSocket)]),
	{ok, Pid} = trunk_end:start_link(TrunkSocket, Config),
	
	set_sockopt(ListenSocket, TrunkSocket),
	%gen_tcp:controlling_process(TrunkSocket, Pid),
	gen_tcp:send(TrunkSocket, "Hello!\n"),
	gen_tcp:close(TrunkSocket),

	%% Signal the network driver that we are ready to accept another connection
	case prim_inet:async_accept(ListenSocket, -1) of
		{ok,    NewRef} -> ok;
		{error, NewRef} -> exit({async_accept, inet:format_error(NewRef)})
	end,
	{noreply, {ListenSocket, NewRef, Config, Statics}};
handle_info(_UnknwonInfo, Context) ->
	io:format("Got unkown info: ~p\n", [_UnknwonInfo]),
    {noreply, Context}.

handle_call(Request, _From, Context) ->
    {stop, {unknown_call, Request}, Context}.

handle_cast(_Msg, Context) ->
    {noreply, Context}.

 
%%-------------------------------------------------------------------------
%% @spec (Reason, State) -> any
%% @doc  Callback executed on server shutdown. It is only invoked if
%%       `process_flag(trap_exit, true)' is set by the server process.
%%       The return value is ignored.
%% @end
%% @private
%%-------------------------------------------------------------------------
terminate(_Reason, {ListenSocket, _Ref, _Config, _Status}) ->
    gen_tcp:close(ListenSocket),
    ok.
 
%%-------------------------------------------------------------------------
%% @spec (OldVsn, State, Extra) -> {ok, NewState}
%% @doc  Convert process state when code is changed.
%% @end
%% @private
%%-------------------------------------------------------------------------
code_change(_OldVsn, Context, _Extra) ->
    {ok, Context}.

%% Taken from prim_inet.  We are merely copying some socket options from the
%% listening socket to the new client socket.
set_sockopt(ListSock, CliSocket) ->
    true = inet_db:register_socket(CliSocket, inet_tcp),
    case prim_inet:getopts(ListSock, [active, nodelay, keepalive, delay_send, priority, tos]) of
    {ok, Opts} ->
        case prim_inet:setopts(CliSocket, Opts) of
        ok    -> ok;
        Error -> gen_tcp:close(CliSocket), Error
        end;
    Error ->
        gen_tcp:close(CliSocket), Error
    end.


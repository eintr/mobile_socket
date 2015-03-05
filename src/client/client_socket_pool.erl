-module(client_socket_pool).
-behaviour(gen_server).

-export([start_link/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).

start_link(Config) ->
	gen_server:start_link({global, socket_end_pool}, ?MODULE, [Config], []).

init([Config]) ->
	erase(),
	{ok, {Config, [{socket_end_count, 0}]}}.

handle_info({terminate}, Context) ->
	{stop, "Demand termination.", ok, Context};
handle_info(Request, Context) ->
	io:format("Ignored info: ~p\n", [Request]),
    {noreply, Context}.

handle_cast(Msg, Context) ->
	io:format("Ignored cast: ~p\n", [Msg]),
    {noreply, Context}.

handle_call({enumall}, From, {Config, Statics}=Context) ->
	{reply, enumall_socketend(), Context};
handle_call({get_socket_end, Host}, From, {Config, Statics}=Context) ->
	case get(Host) of
		{Pid, RefCount} ->
			put(Host, {Pid, RefCount+1}),
			{reply, {socket_end_pid, Pid}, Context};
		undefined ->
			case gen_tcp:connect(kv:get('ServerAddr', Config), kv:get('ServerPort', Config), [binary, {packet, 2}, {active, false}]) of
				{ok, Socket} ->
					{ok, Pid} = client_socket_end:start_link([Socket, Config]),
					put(Host, {Pid, 1}),
					{reply, {socket_end_pid, Pid}, Context};
				{error, Reason} ->
					{reply, {error, Reason}, Context}
			end
	end;
handle_call({close_socket_end, Host}, From, {Config, Statics}=Context) ->
	case get(Host) of
		{Pid, 1} ->
			Pid ! {self(), terminate},
			erase(Host),
			{reply, ok, Context};
		{Pid, RefCount} ->
			put(Host, {Pid, RefCount-1}),
			{reply, ok, Context};
		undefined ->
			{reply, not_found, Context}
	end.

code_change(_OldVsn, Context, _Extra) ->
    {ok, Context}.

terminate(Reason, {Config, Status}) ->
	io:format("~p terminated since ~p\n", [?MODULE, Reason]),
	cleanup_socket_ends(),
    ok.

cleanup_socket_ends() ->
	cleanup_socket_end(get()).
cleanup_socket_end(undefined) ->
	ok;
cleanup_socket_end({Pid}) ->
	Pid ! {self(), terminate},
	cleanup_socket_end(get()).

enumall_socketends() ->
	enum_socketend(get(), []).

    Collector = fun({Addr, Pid}) ->
        Pid ! {report, self()},
        receive
            M -> M
        after 1000 ->
            io_lib:format("Server ~p => addr_server didnt response.\n", [Addr])
        end
    end,
    Translater = fun({{{A, B, C, D}, Port}, {Queue, EstDelay, {MaxCDelay, MaxRDelay, MaxSDelay}}}) ->
        io_lib:format("Server ~b.~b.~b.~b:~b => Configured Delay: {~p, ~p, ~p}, Queuelen: ~p, EstDelay: ~pms\n", [A, B, C, D, Port, MaxCDelay, MaxRDelay, MaxSDelay, length(Queue), EstDelay])
    end,
    qdict ! {enum_all, self()},
    receive
        {enum_all, List} ->
            lists:map(Translater,
                serverlist_sort(fun
                    ({_, {_, EstDelay, _}}) -> -EstDelay end, lists:map(Collector, List)));
        _Msg ->
            "Cant enum servers"
    end.



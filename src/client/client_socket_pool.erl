-module(client_socket_pool).
-behaviour(gen_server).

-export([start_link/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).

start_link(Config) ->
	gen_server:start_link({local, socket_end_pool}, ?MODULE, [Config], []).

init([Config]) ->
	erase(),
	io:format("Start socket_end_pool service.\n"),
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
	{reply, enumall_socketends(), Context};
handle_call({get_socket_end, Host}, From, {Config, Statics}=Context) ->
	io:format("Got get_socket_end request from ~p\n", [From]),
	case get(Host) of
		{Pid, RefCount} ->
			io:format("There is already a socket_end(~p) for host ~p, multiplex.\n", [Pid, Host]),
			put(Host, {Pid, RefCount+1}),
			{reply, {socket_end_pid, Pid}, Context};
		undefined ->
			io:format("No socket_end for host ~p, create.\n", [Host]),
			{ok, Pid} = client_socket_end:start_link(Config),
			io:format("socket_end(~p) started.\n", [Pid]),
			put(Host, {Pid, 1}),
			{reply, {socket_end_pid, Pid}, Context}
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

enum_socketend([], List) ->
	List;
enum_socketend([{Pid, RefCount}|Tail], List) ->
	Pid ! {self(), enum},
	receive
		M ->
			enum_socketend(Tail, List++[{Pid, RefCount, M}])
	end.


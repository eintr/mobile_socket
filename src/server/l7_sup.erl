-module(l7_sup).
-behaviour(supervisor).

-export([start_link/0, start_link/1, init/1]).

-define(L7_TEST_CONFIG, [
	{l7name, "TestServer"},
	{port, [18080, 18081]},
    {addr, [{0,0,0,0}]},

    {crt_file, "conf/server.crt"},
    {key_file, "conf/server.key"},

    {log_file, "var/log"},
    {log_level, log_info},

    {multiplex_ratio, 5},

    {connect_timeout, 2000},
    {recv_timeout, 2000},

    {upstreams, [
        {"10.75.12.0/24",80},
        {"10.75.12.51",80}]}
	]).

start_link() -> 
	io:format("Using default config.\n"),
	start_link(?L7_TEST_CONFIG).

start_link(L7Config) ->
    supervisor:start_link({local, l7_sup}, l7_sup, L7Config).

init(L7Config) ->
	io:format("l7_sup:init()\n"),
	SockaddrList = [{Addr, Port} || Addr<-config:get(addr, L7Config), Port<-config:get(port, L7Config)],
	io:format("SockaddrList = ~p\n", [SockaddrList]),
	ChildList = lists:map(fun (E)->
		{l7_servername(E), {l7_server, start_link, [E, L7Config]}, permanent, brutal_kill, worker, [l7_server]} end,
		SockaddrList),
	io:format("ChildList = ~p\n", [ChildList]),
	{ok, {{one_for_one, 1000000000000000000000000000000000, 1}, ChildList ++ [
		{log, {log, start_link, [L7Config]}, permanent, brutal_kill, worker, [log]}
	]}}.

l7_servername({{A,B,C,D}, Port}) ->
	list_to_atom(lists:flatten(io_lib:format("l7_on_~b_~b_~b_~b_~b", [A,B,C,D, Port]))).


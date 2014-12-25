-module(l7_sup).
-behaviour(supervisor).

-import(log, [log/2, log/3]).

-export([start_link/0, start_link/1, init/1]).

-define(L7_TEST_CONFIG, [
	{l7name, "TestServer"},
	{port, [18080, 18081]},
    {addr, [{0,0,0,0}]},

    {crt_file, "conf/server.crt"},
    {key_file, "conf/server.key"},

    {log_file, "var/log"},
    {log_level, log_info},

    {connect_timeout, 2000},
    {recv_timeout, 2000},

    {upstreams, [
        {{"10.75.12.51",80}, [  {weight, 1},
                                {max_conns, 1000},
                                resolve ]},
        {{"10.75.12.60",80}, [  {weight, 2},
                                {max_conns, infinite},
                                resolve]} ]}
	]).

start_link() -> 
	start_link(?L7_TEST_CONFIG).

start_link(L7Config) ->
    supervisor:start_link({local, l7_sup}, l7_sup, L7Config).

init(L7Config) ->
	ok = crypto:start(),
	SockaddrList = [{Addr, Port} || Addr<-config:get(addr, L7Config), Port<-config:get(port, L7Config)],
	ChildList = lists:map(fun (E)->
		{l7_servername(E), {l7_server, start_link, [E, L7Config]}, permanent, brutal_kill, worker, [l7_server]} end,
		SockaddrList),
	{ok, {{one_for_one, 10, 1}, ChildList ++ [
		{log, {log, start_link, [L7Config]}, permanent, brutal_kill, worker, [log]}
	]}}.

l7_servername({{A,B,C,D}, Port}) ->
	list_to_atom(lists:flatten(io_lib:format("l7_on_~b_~b_~b_~b_~b", [A,B,C,D, Port]))).


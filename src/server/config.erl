-module(config).

-export([get/2, set/2, load_conf/1]).

-include("config.hrl").

-define(DEFAULT_L7_CONFIG, [
    {port, [80]},
    {addr, ["0.0.0.0"]},
    {admin_port, 8972},

    {crt_file, "conf/server.crt"},
    {key_file, "conf/server.key"},

    {log_file, "var/log"},
    {log_level, log_debug},

    {multiplex_ratio, 5},

    {connect_timeout, 2000},
    {recv_timeout, 2000},

    {upstreams, [
        {{"10.75.12.51",80}, [	{weight, 1},
								{max_conns, 1000},
								resolve	]},
        {{"10.75.12.60",80}, [	{weight, 2},
								{max_conns, infinite},
								resolve]}
	]}  ]).

-define(DEFAULT_CONFIG, [
	{default, ?DEFAULT_L7_CONFIG}	]).

get(Key, Config) ->
    case lists:keyfind(Key, 1, Config) of
        {Key, Value} -> Value;
        false -> false
    end.

set([], Config) ->
	Config;
set({Key, Val}, Config) ->
	lists:keystore(Key, 1, Config, {Key, Val});
set([H|T], Config) ->
	set(T, set(H, Config)).

kvlist_merge([], Background) ->
	Background;
kvlist_merge([{K, V}|T], Background) ->
	kvlist_merge(T, lists:keystore(K, 1, Background, {K, V})).

load_conf(default) ->
	conf_postprocess(?DEFAULT_CONFIG);
load_conf([$/|_]=Filename) ->
	io:format("Load config file: ~p\n", [Filename]),
	{ok, Value} = file:script(Filename),
	%io:format("Raw: ~p\n", [Value]),
	Conf = kvlist_merge(Value, ?DEFAULT_CONFIG),
	%io:format("Combined with default: ~p\n", [Conf]),
	conf_postprocess(Conf);
load_conf([Filename]) ->
	load_conf(?PREFIX++"/"++atom_to_list(Filename)).

conf_postprocess(Conf) ->
	Logfile_replaced = lists:keyreplace(log_file, 1, Conf, {log_file, ?PREFIX++"/"++get(log_file, Conf)}),
	io:format("Config loaded: ~p\n", [Logfile_replaced]),
	Logfile_replaced.


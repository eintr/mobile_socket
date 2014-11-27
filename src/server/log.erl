-module(log).
-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3]).

-export([log/2, log/3]).

-import(config, [config/2]).

-author("牛海青<nhf0424@gmail.com>").

-export([log_center_start/2]).

start_link(GenConfig) ->
	gen_server:start_link(?MODULE, [GenConfig], [])

init([GenConfig]) ->
	Path = config:get(log_file, GenConfig),
	case file:open(Path, [append, {encoding, utf8}, sync]) of
		{ok, LogFile} -> % TODO
			register(log_center, spawn_link(?MODULE, log_center_start, [LogFile, Config]));
		{error, Reason} ->
			io:format("Open log [~s] failed: ~s\n", [Path, Reason]),
			{error, Reason}
	end.

log(Level, String) ->
	log_center ! {log, Level, string:strip(String), []}.

log(Level, Format, ArgList) ->
	log_center ! {log, Level, string:strip(Format), ArgList}.

log_center_start(LogFile, Config) ->
	put(log_debug,	{"DEBUG", 0}),
	put(log_info,	{"INFO", 1}),
	put(log_notice,	{"NOTICE", 2}),
	put(log_warning,{"WARNING", 3}),
	put(log_error,	{"ERROR", 4}),
	put(log_critical,{"CRITICAL", 5}),

	LeastLevel = config(log_level, Config),
	{_, LeastLevel_val} = get(LeastLevel),
	log(log_info, "log_center started at level ~p.", [LeastLevel]),
	log_center_loop(LogFile, LeastLevel_val, Config).

log_center_loop(LogFile, LeastLevel, Config) ->
	receive
		{log, Level, Format, ArgList} ->
			{LogLevelString, LogValue} = get(Level),
			if
				LogValue>=LeastLevel ->
					io:format(LogFile, prepend_time(io_lib:format(LogLevelString++": "++Format, ArgList)), []),
					log_center_loop(LogFile, LeastLevel, Config);
				true ->	% Drop low level logs.
					log_center_loop(LogFile, LeastLevel, Config)
			end;
		{'EXIT'} ->
			ok
	end.

prepend_time(String) ->
	timestamp()++" -- "++String++"\n".

timestamp() ->
	{{Year, Month, Day}, {Hour, Minute, Second}} = calendar:local_time(),
	io_lib:format("~p-~p-~p ~p:~p:~p", [Year, Month, Day, Hour, Minute, Second]).


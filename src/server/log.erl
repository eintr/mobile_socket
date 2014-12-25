-module(log).
-author("牛海青<nhf0424@gmail.com>").

-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, code_change/3, terminate/2]).

-export([log/2, log/3]).

start_link(GenConfig) ->
	Ret = gen_server:start_link({local, log_center}, ?MODULE, [GenConfig], []),
	log(log_info, "log_center started."),
	Ret.

init([GenConfig]) ->
	put(log_debug,	{"DEBUG", 0}),
	put(log_info,	{"INFO", 1}),
	put(log_notice,	{"NOTICE", 2}),
	put(log_warning,{"WARNING", 3}),
	put(log_error,	{"ERROR", 4}),
	put(log_critical,{"CRITICAL", 5}),
	Path = config:get(log_file, GenConfig),
	LeastLevel = config:get(log_level, GenConfig),
	{_, LeastLevel_val} = get(LeastLevel),
	case file:open(Path, [append, {encoding, utf8}, sync]) of
		{ok, LogFile} ->
			%log(log_info, "log_center started at level ~p.", [LeastLevel]),
			{ok, {LogFile, LeastLevel_val, GenConfig}};
		{error, Reason} ->
			io:format("Open log [~s] failed: ~s\n", [Path, Reason]),
			{error, Reason}
	end.

log(Level, String) ->
	gen_server:cast(log_center, {log, Level, string:strip(String), []}).

log(Level, Format, ArgList) ->
	gen_server:cast(log_center, {log, Level, string:strip(Format), ArgList}).

handle_call({log, Level, Format, ArgList}, _From, {LogFile, LeastLevel, _GenConfig}=State) ->
	io:format("Got a log call!\n"),
	{LogLevelString, LogValue} = get(Level),
	if
		LogValue>=LeastLevel ->
			io:format(LogFile, prepend_time(io_lib:format(LogLevelString++": "++Format, ArgList)), []),
			{noreply, State};
		true ->	% Drop low level logs.
			{noreply, State}
	end;
handle_call('EXIT', _From, {LogFile, _LeastLevel, _GenConfig}=State) ->
	{LogLevelString, _LogValue} = get(log_info),
	io:format(LogFile, prepend_time(io_lib:format(LogLevelString++": "++"log service exit.")), []),
	{stop, "", State}.

handle_cast({log, Level, Format, ArgList}, {LogFile, LeastLevel, _GenConfig}=State) ->
	io:format("Got a log cast!\n"),
	{LogLevelString, LogValue} = get(Level),
	if
		LogValue>=LeastLevel ->
			io:format(LogFile, prepend_time(io_lib:format(LogLevelString++": "++Format, ArgList)), []),
			{noreply, State, infinity};
		true ->	% Drop low level logs.
			{noreply, State, infinity}
	end;
handle_cast('EXIT', {LogFile, _LeastLevel, _GenConfig}=State) ->
	{LogLevelString, _LogValue} = get(log_info),
	io:format(LogFile, prepend_time(io_lib:format(LogLevelString++": "++"log service exit.")), []),
	{stop, "", State}.

handle_info(_, State) ->
	{noreply, State}.

code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

terminate(_Reason, _State) ->
	ok.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%5

prepend_time(String) ->
	timestamp()++" -- "++String++"\n".

timestamp() ->
	{{Year, Month, Day}, {Hour, Minute, Second}} = calendar:local_time(),
	io_lib:format("~p-~p-~p ~p:~p:~p", [Year, Month, Day, Hour, Minute, Second]).


-module(flow_end).
-behaviour(gen_fsm).

-export([start_link/3]).
-export([init/1, handle_info/3, relay/2, terminate/3]).

-import(log, [log/2, log/3]).

start_link(Pid_trunk_end, UpstreamAddr, Flowid) ->
	gen_fsm:start_link(?MODULE, [Pid_trunk_end, UpstreamAddr, Flowid], []).

init([TrunkEnd, {IP, Port}, FlowID]) ->
	{ok, Upstream} = gen_tcp:connect(IP, Port, [binary, {active, false}]),
	log(log_info, "Connected to upstream ~p:~p", [IP, Port]),
	{ok, relay, {TrunkEnd, Upstream, FlowID, [{upstream, Upstream}]}}.

handle_info(Info, StateName, State) ->
	?MODULE:StateName(Info, State).

relay({tcp, Upstream, Data}, {TrunkEnd, Upstream, FlowID, _Context}=State) ->
	TrunkEnd ! {flowdata, FlowID, Data},
	{next_state, relay, State};
relay({tcp_close, Upstream}, {TrunkEnd, Upstream, FlowID, _Context}=State) ->
	TrunkEnd ! {flowctl, close, FlowID},
	{stop, "Upstream closed.", State};
relay({flowdata, Data}, {_TrunkEnd, Upstream, _FlowID, _Context}=State) ->
	ok = gen_tcp:send(Upstream, Data),
	{next_state, relay, State};
relay({flowctl, close}, State) ->
	{stop, "Got flow_end close request.", State};
relay(_Msg, State) ->
	log(log_error, "Ignored unknown message: ~p", [_Msg]),
	{next_state, relay, State}.

terminate(_Reason, _StateName, {_TrunkEnd, Upstream, _FlowID, _Context}) ->
	gen_tcp:close(Upstream).

setenv(K, V, Env) ->
    lists:keystore(K, 1, Env, {K, V}).

getenv(K, Env) ->
    case lists:keyfind(K, 1, Env) of
        {K, V} ->
            V;
        false ->
            []
    end.

setenvs(Env, []) ->
    Env;
setenvs(Env, [{K, V}|T]) ->
    setenvs(setenv(K, V, Env), T).

context(K, C) ->
    config:get(K, C).


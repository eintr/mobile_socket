-module(pipeline_end).
-behaviour(gen_fsm).

-export([start_link/3]).
-export([init/1, handle_info/3, relay/2, terminate/3]).

-import(log, [log/2, log/3]).

start_link(Pid_trunk_end, UpstreamAddr, PipelineCFG) ->
	gen_fsm:start_link(?MODULE, [Pid_trunk_end, UpstreamAddr, PipelineCFG], []).

init([TrunkEnd, {IP, Port}, {FlowID, CryptFlag, Zip, MaxDelay, ReplyFlags, Data}=PipelineCFG]) ->
	log(log_info, "Creating pipeline with: ~p.", [PipelineCFG]),
	{ok, Upstream} = gen_tcp:connect(IP, Port, [binary, {active, true}]),
	log(log_info, "Connected to upstream ~p:~p", [IP, Port]),
	case Data of
		<<>> -> skip;
		_ ->
			gen_tcp:send(Upstream, Data),
			log(log_info, "Sent [~p] to upstream while creating pipeline.", [Data])
	end,
	{ok, relay, {TrunkEnd, Upstream, FlowID, CryptFlag, Zip, [{upstream, Upstream}, {maxdelay, MaxDelay}, {replycrypt, ReplyFlags}, {replyzip, ReplyFlags}]}}.

handle_info(Info, StateName, State) ->
	?MODULE:StateName(Info, State).

relay({tcp, Upstream, Data}, {TrunkEnd, Upstream, FlowID, CryptFlag, Zip, _Context}=State) ->
	TrunkEnd ! {flowdata, FlowID, CryptFlag, Zip, Data},
	log(log_info, "Relaying data: ~p", [{flowdata, FlowID, CryptFlag, Zip, Data}]),
	{next_state, relay, State};
relay({tcp_closed, Upstream}, {TrunkEnd, Upstream, FlowID, CryptFlag, Zip, _Context}=State) ->
	TrunkEnd ! {flowctl, close, {FlowID, CryptFlag, Zip}},
	log(log_info, "Upstream(~p) closed.", [Upstream]),
	{stop, normal, State};
relay({flowdata, Data}, {_TrunkEnd, Upstream, _FlowID, CryptFlag, Zip, _Context}=State) ->
	ok = gen_tcp:send(Upstream, Data),
	{next_state, relay, State};
relay({flowctl, close}, State) ->
	log(lof_info, "flow_end: Got close request."),
	{stop, normal, State};
relay(_Msg, State) ->
	log(log_error, "Ignored unknown message: ~p", [_Msg]),
	{next_state, relay, State}.

terminate(_Reason, _StateName, {_TrunkEnd, Upstream, _FlowID, CryptFlag, Zip, _Context}) ->
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


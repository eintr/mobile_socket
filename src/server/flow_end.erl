-module(framer).
-behaviour(gen_fsm).

-export([start_link/0, start_link/1]).
-export([init/2]).

-import(log, [log/2, log/3]).

start_link(Trunk_end_pid, ) ->
create(TruncerHUB, Prio, FlowID, Request) ->
	Header = binary_to_list(Request),
	spawn(fun ()-> framer(connect_upstream, [	{trunkerhub, TruncerHUB},
												{flowid, FlowID},
												{prio, Prio},
												{request, Request}]	) end).

framer(connect_upstream, Context) ->
	{ok, Upstream} = gen_tcp:connect("127.0.0.1", 8000, [binary, {packet, fcgi}, {active, false}], 2000), % TODO: Extract from Context/request
	framer(send_request, Context++[upstram_socket, Upstream]);

framer(send_request, Context) ->
	gen_tcp:controlling_process(UpstreamSocket, self()),
	inet:setopts(UpstreamSocket, [{active, true}]),
	framer(relay_reply, Context);

framer(relay_reply, Context) ->
	receive
		% From upstream socket side.
        {tcp, Socket, <<1:8, ?FCGI_STDOUT:8, _ReqId:16/big-integer, Len:16/big-integer, _:16, Body/binary >>} ->
            << Data:Len/binary, _tail/binary >> = Body,
            %io:format("~s", [binary_to_list(Data)]),
			context(trunkerhub, Context) ! {data, context(flowid, Context), context(prio, Context), Data},
            framer(relay_reply, Context);
        {tcp, Socket, <<1:8, ?FCGI_END_REQUEST:8, _ReqId:16/big-integer, Length:16/big-integer, _:16, Body/binary >>} ->
            %io:format("\n"),
			context(trunkerhub, Context) ! {ctl, framer, close, [context(flowid, Context)]},
            framer(relay_reply, Context);
        {tcp, Socket, <<1:8, Type:8, _ReqId:16/big-integer, Length:16/big-integer, _:16, Body/binary >>} ->
            io:format("Got msg type=~b\n", [Type]),
            framer(relay_reply, Context);
		{tcp_error, Socket, Reason} ->
			context(trunkerhub, Context) ! {ctl, framer, failure, [context(flowid, Context), Reason]},
			framer(term, Context);

		% From trunker side.
		{data, _FlowID, _Prio, Data} ->
			fcgi_send_record(context(upstram_socket, Context), ?FCGI_STDIN, 1, Data),
			framer(relay_reply, Context);
		{ctl, framer, open, [Prio, FlowID, ReqHeader]=Args} ->
			UpstreamSocket = context(upstram_socket, Context),
    		Env = setenvs(?DefaultEnv, [{"REQUEST_URI", "/test.php"}, {"SCRIPT_FILENAME", "/fcgi/test.php"}, {"QUERY_STRING", []}]),	% TODO: Extract from Context/request
            send_fcgi_request(UpstreamSocket, CurrentReqID, Env),
			framer(relay_reply, Context);
		{ctl, framer, close, [_FlowID]} ->
			log(log_debug, "Flow exit by peer request."),
			framer(term, Context);
		UnknownMsg ->
			log(log_error, "framer got unknown message: ~p", [UnknownMsg])
	end;

framer(term, Context) ->
	context(trunkerhub, Context) ! {ctl, trunker, unregister_framer, [context(flowid, Context)]},
	ok.

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
    config:config(K, C).


% FASTCGI protocol things:

send_fcgi_request(Socket, ReqID, CustomEnv) ->
    Env = setenvs(?DefaultEnv, CustomEnv),
    fcgi_send_record(Socket, ?FCGI_BEGIN_REQUEST, ReqID, <<1:16,0:8,0:40>>),
    fcgi_send_record(Socket, ?FCGI_PARAMS, 1, Env),
    fcgi_send_record(Socket, ?FCGI_PARAMS, 1, []),
    ok.

% FASTCGI Message Format:
% <<Version:8, Type:8, RequestId:16, ContentLength:16, PaddingLength:8, Reserved:8,Str/binary >>
recv_msg(Socket) ->
    receive
        {tcp, Socket, <<1:8, ?FCGI_STDOUT:8, _ReqId:16/big-integer, Len:16/big-integer, _:16, Body/binary >>} ->
            << Data:Len/binary, _tail/binary >> = Body,
            io:format("~s", [binary_to_list(Data)]),
            recv_msg(Socket);
        {tcp, Socket, <<1:8, ?FCGI_END_REQUEST:8, _ReqId:16/big-integer, Length:16/big-integer, _:16, Body/binary >>} ->
            io:format("\n"),
            recv_msg(Socket);
        {tcp, Socket, <<1:8, Type:8, _ReqId:16/big-integer, Length:16/big-integer, _:16, Body/binary >>} ->
            io:format("Got msg type=~b\n", [Type]),
            recv_msg(Socket);
        {tcp_closed, Socket} ->
            io:format("Upstream closed.\n");
        _other ->
            io:format("Unknown format msg: ~p\n", [_other]),
            recv_msg(Socket),
            error
    after 3000 ->
        io:format("Time out.~n")
    end.

%%发送选项
fcgi_send_record(Socket, Type, RequestId, NameValueList) ->
    EncodedRecord = fcgi_encode_record(Type, RequestId,NameValueList),
    gen_tcp:send(Socket, EncodedRecord).

%%组包
fcgi_encode_record(Type, RequestId, NameValueList) when is_list(NameValueList) ->
    fcgi_encode_record(Type, RequestId, fcgi_encode_name_value_list(NameValueList));

%%判断ContentData是否满8字节,否则填充
fcgi_encode_record(Type, RequestId, ContentData) when is_binary(ContentData) ->
    ContentLength = size(ContentData),
    PaddingLength = if
        ContentLength rem 8 == 0 ->
            0;
        true ->
            8 - (ContentLength rem 8)
        end,
    %%填充数据,每8字节组包        不足用0填充       
    PaddingData = <<0:(PaddingLength*8)>>,
    Version = 1,
    Reserved = 0,
    <<Version:8,
      Type:8,
      RequestId:16,
      ContentLength:16,
      PaddingLength:8,
      Reserved:8,
      ContentData/binary,
      PaddingData/binary >>.

%%将环境变量组成binary
fcgi_encode_name_value_list(_NameValueList = []) ->
    << >>;
fcgi_encode_name_value_list(_NameValueList = [{Name, Value} | Tail]) ->
    <<(fcgi_encode_name_value(Name,Value))/binary,(fcgi_encode_name_value_list(Tail))/binary >>.
fcgi_encode_name_value(Name, _Value = undefined) ->
    fcgi_encode_name_value(Name, "");
fcgi_encode_name_value(Name, Value) when is_list(Name) and is_list(Value) ->
    NameSize = length(Name),
    NameSizeData = << NameSize:8 >>,
    ValueSize = length(Value),
    ValueSizeData = <<ValueSize:8 >>,
    << NameSizeData/binary, ValueSizeData/binary, (list_to_binary(Name))/binary, (list_to_binary(Value))/binary >>.


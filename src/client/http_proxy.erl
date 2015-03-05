-module(http_proxy).

-export([http_proxy_callback/2]).

-include_lib("kernel/include/inet.hrl").

http_proxy_callback(Client_socket, [Config]) ->
	io:format("log_debug: Got connection.\n"),
	gen_tcp:controlling_process(Client_socket, self()),
	%inet:setopts(Client_socket, [{active, true}]),
	http_proxy_protocol(Client_socket, Config).

http_proxy_protocol(Client_socket, Config) ->
	io:format("recv_request\n"),
	http_proxy_protocol(recv_line1, Client_socket, Config, []).

http_proxy_protocol(recv_line1, Client_socket, Config, HttpHdr) ->
	{ok, Bin} = gen_tcp:recv(Client_socket, 128),
	case parse_line1(<<HttpHdr/binary, Bin/binary>>) of
		{ok, Line1} ->
			{ok, Host} = parse_host(Line1),
			http_proxy_protocol(get_socketend, Client_socket, Config++[{host, Host}], <<HttpHdr/binary, Bin/binary>>);
		continue ->
			http_proxy_protocol(recv_line1, Client_socket, Config, <<HttpHdr/binary, Bin/binary>>);
        Unknown ->
            io:format("log_error: Unknown: ~p", [Unknown]),
			http_proxy_protocol(term, Client_socket, Config, <<HttpHdr/binary, Bin/binary>>)
	end;

http_proxy_protocol(get_socketend, Client_socket, Config, HttpHdr) ->
	case gen_server:call(socket_end_pool, {get_socket_end, kv:get(host, Config)}) of
		{socket_end_pid, SocketEndPid} ->
			http_proxy_protocol(get_pipelineid, Client_socket, Config++[{socket_end_pid, SocketEndPid}], HttpHdr);
		{error, _Reason} ->
			http_proxy_protocol(error, Client_socket, Config, HttpHdr)
	end;

http_proxy_protocol(get_pipelineid, Client_socket, Config, HttpHdr) ->
	kv:get(socket_end_pid, Config) ! {self(), get_pipelineid},
	receive
		{id, ID} ->
			http_proxy_protocol(open_pipeline, Client_socket, Config++[{pipeline_id, ID}], HttpHdr);
		R ->
			{error, R}
	end;

http_proxy_protocol(open_pipeline, Client_socket, Config, HttpHdr) ->
	kv:get(socket_end_pid, Config) ! {self(), ctl, pipeline, open, {kv:get(pipeline_id, Config), 0, 0, 1000, 0, HttpHdr}},
	receive
		ok ->
			http_proxy_protocol(relay, Client_socket, Config, HttpHdr)
	end;

http_proxy_protocol(relay, Client_socket, Config, HttpHdr) ->
	io:format("relaying: ~p\n", [Config]),
	http_proxy_protocol(relay_loop, Client_socket, Config, HttpHdr);

http_proxy_protocol(relay_loop, Client_socket, Config, HttpHdr) ->
	receive
		{data, RawData} ->
			gen_tcp:send(Client_socket, RawData),
			http_proxy_protocol(relay_loop, Client_socket, Config, HttpHdr);
		{ctl, pipeline, close} ->
			http_proxy_protocol(term, Client_socket, Config, HttpHdr);
		{ctl, pipeline, failure} ->
			io:format("Peer failure."),
			http_proxy_protocol(term, Client_socket, Config, HttpHdr);
		{tcp, Client_socket, RawData} ->
			kv:get(socket_end_pid, Config) ! {self(), data, kv:get(pipeline_id, Config), 0, 0, RawData},
			http_proxy_protocol(relay_loop, Client_socket, Config, HttpHdr);
		{tcp_close, Client_socket} ->
			kv:get(socket_end_pid, Config) ! {self(), ctl, pipeline, close, {kv:get(pipeline_id, Config), 0, 0}},
			http_proxy_protocol(term, Client_socket, Config, HttpHdr);
		M ->
			io:format("Got unknown message: ~p\n", [M])
	end,
	http_proxy_protocol(relay_loop, Client_socket, Config, HttpHdr);

http_proxy_protocol(term, Client_socket, _Config, _HttpHdr) ->
	io:format("terminating\n"),
	gen_tcp:close(Client_socket),
	ok.

parse_line1(Bin) ->
	case binary:match(Bin, <<"\r\n">>) of
		{Start, Len} ->
			{ok, binary:part(Bin, Start, Len)};
		nomatch ->
			continue
	end.

parse_host(Bin) ->
	TMP1 = lists:nth(2, binary:split(Bin, <<"//">>)),
	HostPort = lists:nth(1, binary:split(TMP1, <<"/">>)),
	{ok, lists:nth(1, binary:split(HostPort, <<":">>))}.


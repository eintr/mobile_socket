-module(burst_prio_queue).

-export([new/2, start/2]).

-import(log, [log/2, log/3]).

new(Trunk_socket, Config) ->
	spawn(?MODULE, start, [Trunk_socket, Config]).

start(Trunk_socket, Config) ->
	BurstThreashHold = config:config(burst_thresh_hold, Config),
	PowerTailLen = config:config(pow_tail_len, Config),
	IdleLen = config:config(idle_len, Config),
	MaxDelay = config:config(max_delay, Config),
	loop(connected, 0, Trunk_socket, {BurstThreashHold, PowerTailLen, IdleLen, MaxDelay}, queuearray_new(), 0).

loop(connected, Timer, Trunk_socket, {_, PowerTailLen, _, _}=Config, QueueArray, 0) when Timer>PowerTailLen->
	loop(idle, 0, Trunk_socket, Config, QueueArray, 0);
loop(connected, Timer, Trunk_socket, {_, _, _, MaxDelay}=Config, QueueArray, _) when Timer>MaxDelay ->
	flush(Trunk_socket, QueueArray),
	loop(connected, 0, Trunk_socket, Config, queuearray_new(), 0);
loop(connected, Timer, Trunk_socket, {BurstThreashHold, _PowerTailLen, _IdleLen, _MaxDelay}=Config, QueueArray, QCount) ->
	receive
		connected ->
			loop(connected, Timer, Trunk_socket, Config, QueueArray, QCount);
		{enqueue, Prio, Frame} ->
			NewQ = array:set(Prio, array:get(Prio, QueueArray)++[Frame], QueueArray),
			if
				QCount + length(Frame) > BurstThreashHold ->
					flush(Trunk_socket, QueueArray),
					loop(connected, 0, Trunk_socket, Config, queuearray_new(), 0);
				true ->
					loop(connected, Timer, Trunk_socket, Config, NewQ, QCount + byte_size(Frame))
			end
		after 1000 ->
			loop(connected, Timer+1000, Trunk_socket, Config, QueueArray, QCount)
	end;

loop(idle, Timer, Trunk_socket, {_, _, _, MaxDelay}=Config, QueueArray, QCount) when (QCount>0) and (Timer>MaxDelay) ->
	loop(connected, Timer, Trunk_socket, Config, QueueArray, QCount);
loop(idle, Timer, Trunk_socket, {BurstThreashHold, _PowerTailLen, _IdleLen, _MaxDelay}=Config, QueueArray, QCount) ->
	receive
		connected ->
			log(log_debug, "~b bytes deferred sending for power saving.", [QCount]),
			flush(Trunk_socket, QueueArray),
			loop(connected, 0, Trunk_socket, Config, queuearray_new(), 0);
		{enqueue, 0, Frame} ->
			NewQ = array:set(0, array:get(0, QueueArray)++[Frame], QueueArray),
			flush(Trunk_socket, NewQ),
			loop(connected, 0, Trunk_socket, Config, queuearray_new(), 0);
		{enqueue, Prio, Frame} ->
			NewQ = array:set(Prio, array:get(Prio, QueueArray)++[Frame], QueueArray),
			if
				QCount + length(Frame) > BurstThreashHold ->
					flush(Trunk_socket, QueueArray),
					loop(connected, 0, Trunk_socket, Config, queuearray_new(), 0);
				true ->
					loop(idle, Timer, Trunk_socket, Config, NewQ, QCount + length(Frame))
			end
		after 1000 ->
			loop(idle, Timer+1000, Trunk_socket, Config, QueueArray, QCount)
	end.
	


queuearray_new() ->
	array:new([{size, 8}, {fixed, true}, {default, []}]).

flush(Socket, Q) ->
	flush_prio(0, Socket, Q).

flush_prio(8, _, _) ->
	ok;
flush_prio(N, Socket, Q) ->
	lists:foreach(fun (Frame)-> gen_tcp:send(Socket, Frame) end, array:get(N, Q)),
	flush_prio(N+1, Socket, Q).


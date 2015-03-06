-module(kv).

-export([get/2, set/3, erase/2, inc/2, dec/2]).

get(Key, List) ->
    case lists:keyfind(Key, 1, List) of
        {Key, Value} ->
            Value;
        false ->
            undefined;
		M ->
			io:format("get(~p, ~p)=~p\n", [Key, List, M])
    end.

set(Key, Value, List) ->
	lists:keystore(Key, 1, List, {Key, Value}).

erase(Key, List) ->
	lists:keydelete(Key, 1, List).

fupdate(Key, Function, List) when is_function(Function) ->
	set(Key, Function(get(Key, List)), List).

inc(Key, List) ->
	fupdate(Key, fun
		(undefined)-> 1;
		(N) -> N+1
	end, List).

dec(Key, List) ->
	fupdate(Key, fun
		(undefined)-> -1;
		(N) -> N-1
	end, List).


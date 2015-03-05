include ../config.mk

sources=client.erl client_socket_pool.erl http_proxy.erl mycrypt.erl client_socket_end.erl frame.erl kv.erl simple_tcp_server.erl

beams=$(sources:.erl=.beam)

all: $(beams)

%.beam: %.erl
	erlc $^

clean:
	rm -f $(beams)


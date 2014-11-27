include ../config.mk

#sources=simple_tcp_server.erl config.erl log.erl mycrypt.erl frame.erl trunker.erl weibo_fcgi.erl framer.erl fastcgi_client.erl
sources=l7_server.erl  l7_sup.erl

beams=$(sources:.erl=.beam)

all: deps service_start $(beams)

%.beam: %.erl
	erlc $^

deps: config.hrl

config.hrl: config.hrl.tmpl
	@echo "Generating $@"
	@echo $(PREFIX) | sed 's/\//\\\//g' > /tmp/~rash_socks_make.template
	@sed "s/__PREFIX__/`cat /tmp/~rash_socks_make.template`/g" $< > $@
	@rm -f /tmp/~id_service_make.template

service_start: service_start.tmpl ../config.mk
	@echo "Generating $@"
	@echo $(PREFIX) | sed 's/\//\\\//g' > /tmp/~rash_socks_make.template
	@sed "s/__PREFIX__/`cat /tmp/~rash_socks_make.template`/g" $< > $@
	@rm -f /tmp/~id_service_make.template
	@chmod a+x $@

install:
	cp *.beam ../dist/ebin/
	cp rash_socks.conf ../dist/conf/

clean:
	rm -f $(beams) rash_socks_start config.hrl


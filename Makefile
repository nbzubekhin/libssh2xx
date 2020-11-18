LIB_DEPS=-lssh2 -lpthread

example:
	g++ -o ssh2-tunnel-example $(LIB_DEPS) ssh2_tunnel.cc test_ssh2_tunnel.cc

all: example

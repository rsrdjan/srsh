# srsh Makefile Copyright 2024 Srdjan Rajcevic <srdjan.rajcevic AT sectreme.com>

CC =cc
LIBS=-lssl -lcrypto -lpthread

server: srsh-server.c
	$(CC) -o srsh-server srsh-server.c $(LIBS)
agent: srsh-agent.c
	$(CC) -o srsh-agent srsh-agent.c $(LIBS)
cert:
	openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 \
	-keyout priv.key -out cert.crt
clean:
	rm -rf *.o

CC := gcc
LDFLAGS := -lssl -lcrypto
UNAME := $(shell uname)
CERT := openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem

ifeq ($(UNAME), Darwin)
CFLAGS := -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

all:
	$(CERT)

all: client server

client: client.o
	$(CC) $(CFLAGS) -o client client.o $(LDFLAGS)

client.o: client.c
	$(CC) $(CFLAGS) -c client.c

server: server.o
	$(CC) $(CFLAGS) -o server server.o $(LDFLAGS)

server.o: server.c
	$(CC) $(CFLAGS) -c server.c

clean:
	rm -f server server.o client client.o

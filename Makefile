SERVER_SOURCES = src/server.c
SERVER_HEADERS =

CLIENT_SOURCES = src/client.c src/parser.c
CLIENT_HEADERS = src/parser.h

TARGETS = server client
META = Makefile README.md group.txt

CFLAGS = -Wall -Wextra -std=gnu99 -g3
CC = gcc

.PHONY: all tarball clean

all: $(TARGETS)

tarball: sp-assignment1.tar.gz

sp-assignment1.tar.gz: $(SERVER_SOURCES) $(SERVER_HEADERS) \
											 $(CLIENT_HEADERS) $(CLIENT_SOURCES) $(META)
	tar -czf $@ $^

clean:
	rm -f $(TARGETS)
	rm -f *.db
	rm -f clientkeys/*.*
	rm -f serverkeys/*.*
	rm -f *.tar.gz
	rm -f src/*.o

server: $(SERVER_SOURCES:.c=.o)
	$(CC) $(CFLAGS) -o $@ $^

$(SERVER_SOURCES:.c=.o): $(SERVER_HEADERS)

client: $(CLIENT_SOURCES:.c=.o)
	$(CC) $(CFLAGS) -o $@ $^

$(CLIENT_SOURCES:.c=.o): $(CLIENT_HEADERS)

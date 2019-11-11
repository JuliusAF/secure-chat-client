SERVER_SOURCES = src/server.c src/parser.c \
								 src/safe_wrappers.c src/network.c \
								 src/database.c
SERVER_HEADERS = src/parser.h src/safe_wrappers.h \
								 src/network.h src/database.h

CLIENT_SOURCES = src/client.c src/parser.c src/safe_wrappers.c src/network.c
CLIENT_HEADERS = src/parser.h src/safe_wrappers.h src/network.h

TARGETS = server client
META = Makefile README.md group.txt

CFLAGS = -Wall -Wextra -std=gnu99 -g3
LDFLAGS =
LIBS = -lsqlite3

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
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

$(SERVER_SOURCES:.c=.o): $(SERVER_HEADERS)

client: $(CLIENT_SOURCES:.c=.o)
	$(CC) $(CFLAGS) -o $@ $^

$(CLIENT_SOURCES:.c=.o): $(CLIENT_HEADERS)

SERVER_SOURCES = src/server.c src/parser.c \
								 src/safe_wrappers.c src/network.c \
								 src/database.c src/server_utilities.c
SERVER_HEADERS = src/parser.h src/safe_wrappers.h \
								 src/network.h src/database.h \
								 src/server_utilities.h

CLIENT_SOURCES = src/client.c src/parser.c \
								 src/safe_wrappers.c src/network.c \
								 src/client_utilities.c
CLIENT_HEADERS = src/parser.h src/safe_wrappers.h \
								 src/network.h src/client_utilities.h

TARGETS = server client
KEYS = ca-key.pem ca-cert.pem server-key.pem server-csr.pem server-ca-cert.pem
META = Makefile README.md group.txt

CFLAGS = -Wall -Wextra -std=gnu99 -g3
LDFLAGS =
LIBS = -lsqlite3 -lcrypto -lssl

CC = gcc

.PHONY: all tarball clean

all: $(TARGETS) $(KEYS)

tarball: sp-assignment1.tar.gz

sp-assignment1.tar.gz: $(SERVER_SOURCES) $(SERVER_HEADERS) \
											 $(CLIENT_HEADERS) $(CLIENT_SOURCES) $(META) \
											 ttpkeys serverkeys clientkeys
	tar -czf $@ $^

clean:
	rm -f $(TARGETS) *.tar.gz *.pem *.db
	rm -f clientkeys/*.pem
	rm -f serverkeys/*.pem
	rm -f ttpkeys/*.pem ttpkeys/*.srl
	rm -f src/*.o

server: $(SERVER_SOURCES:.c=.o)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

$(SERVER_SOURCES:.c=.o): $(SERVER_HEADERS)

client: $(CLIENT_SOURCES:.c=.o)
	$(CC) $(CFLAGS) -o $@ $^

$(CLIENT_SOURCES:.c=.o): $(CLIENT_HEADERS)

ca-cert.pem: ttpkeys/ca-key.pem
	openssl req -new -x509 -key ttpkeys/ca-key.pem -out ttpkeys/ca-cert.pem -nodes -subj '/CN=ca\.example\.com/'

ca-key.pem:
	openssl genrsa -out ttpkeys/ca-key.pem

server-ca-cert.pem: ttpkeys/ca-cert.pem ttpkeys/ca-key.pem serverkeys/server-csr.pem
	openssl x509 -req -CA ttpkeys/ca-cert.pem -CAkey ttpkeys/ca-key.pem -CAcreateserial -in serverkeys/server-csr.pem -out serverkeys/server-ca-cert.pem

server-csr.pem:
	openssl req -new -key serverkeys/server-key.pem -out serverkeys/server-csr.pem -nodes -subj '/CN=server\.example\.com/'

server-key.pem:
	openssl genrsa -out serverkeys/server-key.pem

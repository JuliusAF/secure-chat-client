# the following sources and headers are shared by both applications
SHARED_SOURCES = src/safe_wrappers.c src/network.c \
								 src/ssl-nonblock.c src/cryptography.c \
								 src/parse_user_input.c

SHARED_HEADERS = src/safe_wrappers.h src/parse_client_input.h \
								 src/network.h src/parse_user_input.h \
								 src/ssl-nonblock.h src/cryptography.h

# the following sources are used by the server. All files not included in the shared variable
# is unique to the server
SERVER_SOURCES = src/server.c src/parse_client_input.c \
								 src/database.c src/server_utilities.c \
								 src/server_network.c src/database_utilities.c \
								 $(SHARED_SOURCES)

SERVER_HEADERS = src/database.h src/database_utilities.h \
								 src/server_utilities.h src/server_network.h \
								 $(SHARED_HEADERS)

# the following sources are used by the client. All files not included in the shared variable
# is unique to the client
CLIENT_SOURCES = src/client.c src/client_utilities.c \
								 src/client_network.c src/parse_server_input.c \
								 $(SHARED_SOURCES)

CLIENT_HEADERS = src/client_utilities.h src/client_network.h \
								 $(SHARED_HEADERS) src/parse_server_input.h

TARGETS = server client
KEYS = ca-key.pem ca-cert.pem server-key.pem server-csr.pem server-ca-cert.pem
META = Makefile README.md group.txt

CFLAGS = -Wall -Wextra -std=gnu99 -g3
LIBS = -lsqlite3 -lcrypto -lssl

CC = gcc

.PHONY: all tarball clean

all: $(TARGETS) $(KEYS) copyfiles

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
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(SERVER_SOURCES:.c=.o): $(SERVER_HEADERS)

client: $(CLIENT_SOURCES:.c=.o)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

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

copyfiles:
	cp ttpkeys/ca-cert.pem clientkeys/
	cp ttpkeys/ca-cert.pem serverkeys/
	cp serverkeys/server-ca-cert.pem clientkeys/

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "parser.h"

int create_server_socket(unsigned short port) {
  int fd, r;
  struct sockaddr_in addr;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("failed to create server socket");
    exit(EXIT_FAILURE);
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  r = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
  if (r != 0) {
    perror("failed to bind server socket");
    exit(EXIT_FAILURE);
  }

  r = listen(fd, 0);
  if (r != 0) {
    perror("failed to set server socket to listening");
    exit(EXIT_FAILURE);
  }

  return fd;
}

static int lookup_host_ipv4(const char *hostname, struct in_addr *addr) {
  struct hostent *host;

  host = gethostbyname(hostname);
  while (host) {
    if(host->h_addrtype == AF_INET &&
      host->h_addr_list &&
      host->h_addr_list[0]) {
      memcpy(addr, host->h_addr_list[0], sizeof(*addr));
      return 0;
    }
    host = gethostent();
  }

  return -1;
}

int client_connect(const char *hostname, unsigned short port) {
  struct sockaddr_in addr;
  int fd, r;

  r = lookup_host_ipv4(hostname, &addr.sin_addr);
  if (r != 0) {
    perror("failed to find host");
    exit(EXIT_FAILURE);
  }

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("failed to create client socket");
    exit(EXIT_FAILURE);
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  r = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
  if (r != 0) {
    perror("failed to connect client socket");
    exit(EXIT_FAILURE);
  }
  return fd;
}

int accept_connection(int serverfd) {
  int connfd;

  connfd = accept(serverfd, NULL, NULL);
  if (connfd < 0) {
    perror("failed to accept incoming connection");
    return -1;
  }
  return connfd;
}

char *serialize_command_struct(command_t *n);
command_t *deserialize_command_struct(char *packet);
char *create_packet(char *data, char *metadata);

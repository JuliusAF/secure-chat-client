#ifndef SERVER_UTILITIES_H
#define SERVER_UTILITIES_H

#include <stdbool.h>
#include <sqlite3.h>
#include <openssl/ssl.h>
#include "parser.h"

#define MAX_CLIENTS 30
#define DATE_FORMAT "%Y-%m-%d %H:%M:%S"
/* The server and workers communicate over the pipes.
The communication between them, however, is very simple and
there is no need for elaborate messages. The workers tell the server
if their connection ended with "C" and the worker tells the server,
and vice versa, if the database has updated.*/
#define S_MSG_UPDATE "U"
#define S_MSG_CLOSE "C"
#define S_MSG_LEN 1

typedef struct client_info {
  int connfd;
  SSL *ssl;
  bool is_logged;
  char username[USERNAME_MAX+1];
  time_t last_updated;
} client_t;

void worker(int connfd, int from_parent[2], int to_parent[2]);
void handle_client_input(client_parsed_t *p, client_t *client_info, int pipefd);
void handle_client_register(client_parsed_t *p, client_t *client_info);


#endif

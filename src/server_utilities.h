#ifndef SERVER_UTILITIES_H
#define SERVER_UTILITIES_H

#include "parser.h"
#include <sqlite3.h>

#define MAX_CLIENTS 30
#define DATE_FORMAT "%Y-%m-%d %H:%M:%S"
/* The server and workers communicate over the pipes.
The communication between them, however, is very simple and
there is no need for elaborate messages. The workers tell the server
if their connection ended with "Closed" and the worker tell the server,
and vice versa, if the databse has updated.*/
#define S_MSG_UPDATE "Update"
#define S_MSG_CLOSE "Closed"
#define S_MSG_LEN 6

typedef struct client_info {
  int connfd;
  char username[USERNAME_MAX+1];
  time_t last_updated;
} client_t;

void worker(int connfd, int from_parent[2], int to_parent[2]);
int handle_client_input(command_t *node, client_t *client_info, int pipefd);

#endif

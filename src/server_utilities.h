#ifndef SERVER_UTILITIES_H
#define SERVER_UTILITIES_H

#include "parser.h"
#include <sqlite3.h>

#define MAX_CLIENTS 30
#define DATE_FORMAT "%Y-%m-%d %H:%M:%S"
#define S_MSG_UPDATE "Updated"
#define S_MSG_CLOSE "Closed"

typedef struct client_info {
  int connfd;
  char username[USERNAME_MAX+1];
  time_t last_updated;
} client_t;

void worker(int connfd, int from_parent[2], int to_parent[2]);
int handle_client_input(command_t *node, client_t *client_info, int pipefd);

#endif

#ifndef SERVER_UTILITIES_H
#define SERVER_UTILITIES_H

#include "parser.h"
#include <sqlite3.h>

#define MAX_CLIENTS 30

void worker(int connfd, int from_parent[2], int to_parent[2]);
int handle_client_input(command_t *node, char *user, int connfd);

#endif

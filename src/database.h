#ifndef DATABASE_H
#define DATABASE_H

#include <stdbool.h>
#include <sqlite3.h>
#include "parser.h"

sqlite3 *open_database(void);
int initialize_database(sqlite3 *db);
int handle_db_login(command_t *node, char *user, int connfd);
int handle_db_register(command_t *node, char *user, int connfd);
int handle_db_privmsg(command_t *node, char *user, int connfd);
int handle_db_pubmsg(command_t *node, char *user, int connfd);
int handle_db_users(char *user, int connfd);
int handle_db_exit(char *user);
int fetch_db_message(char* user, time_t t, int connfd);

#endif

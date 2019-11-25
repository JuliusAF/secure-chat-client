#ifndef DATABASE_H
#define DATABASE_H

#include <stdbool.h>
#include <sqlite3.h>
#include "server_utilities.h"
#include "parser.h"

typedef struct database_message {
  char date[60];
  char sender[USERNAME_MAX+1];
  char recipient[USERNAME_MAX+1];
  char message[MESSAGE_MAX+1];
} msg_components;

sqlite3 *open_database(void);
int initialize_database(void);
msg_components *initialize_msg_components(void);
signed long long get_latest_msg_rowid(void);
int handle_db_login(command_t *node, client_t *client_info);
int handle_db_register(command_t *node, client_t *client_info);
int handle_db_privmsg(command_t *node, client_t *client_info);
int handle_db_pubmsg(command_t *node, client_t *client_info);
int handle_db_users(client_t *client_info);
int handle_db_exit(client_t *client_info);
int fetch_db_message(client_t *client_info);
int create_date_string(char *date, time_t t);
void assign_msg_components(msg_components *comps, sqlite3_stmt *res);
void create_db_message(char *dest, msg_components *comps);

#endif

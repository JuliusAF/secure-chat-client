#ifndef DATABASE_H
#define DATABASE_H

#include <stdbool.h>
#include <sqlite3.h>
#include "server_utilities.h"
#include "parse_client_input.h"
#include "database_utilities.h"

/* functions for the initialization of structs defined in this header and for
the database*/
sqlite3 *open_database(void);
int initialize_database(void);

/* functions used to update the database based on what command was invoked
from the client */
signed long long get_latest_msg_rowid(void);
int handle_db_login(client_parsed_t *parsed, client_t *client_info, char *err_msg);
int handle_db_register(client_parsed_t *parsed, client_t *client_info, char *error_msg);
int handle_db_privmsg(client_parsed_t *parsed, client_t *client_info, char *error_msg);
int handle_db_pubmsg(client_parsed_t *parsed, client_t *client_info);
int handle_db_users(client_t *client_info);
int handle_db_exit(client_t *client_info);
 /* functions that deal with fetching information from the database to send
 to the client later */
fetched_userinfo_t *fetch_db_user_info(client_t *client_info);
msg_queue_t *fetch_db_messages(client_t *client_info);
char *fetch_db_users(void);
char *fetch_db_pubkey(char *name, unsigned int *fetchlen, char *err);


#endif

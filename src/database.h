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

typedef struct fetched_user_info {
  unsigned char iv[IV_SIZE+1];
  unsigned int encrypt_sz;
  unsigned char *encrypted_keys;
} fetched_userinfo_t;

sqlite3 *open_database(void);
int initialize_database(void);
msg_components *initialize_msg_components(void);
signed long long get_latest_msg_rowid(void);

int handle_db_login(command_t *node, client_t *client_info);
int handle_db_register(client_parsed_t *parsed, client_t *client_info, char *error_msg);
int handle_db_privmsg(command_t *node, client_t *client_info);
int handle_db_pubmsg(command_t *node, client_t *client_info);
int handle_db_users(client_t *client_info);
int handle_db_exit(client_t *client_info);

fetched_userinfo_t *fetch_db_user_info(client_t *client_info);
bool is_fetched_userinfo_legal(fetched_userinfo_t *f);
void free_fetched_userinfo(fetched_userinfo_t *f);

int fetch_db_message(client_t *client_info);
int create_date_string(char *date, time_t t);
void assign_msg_components(msg_components *comps, sqlite3_stmt *res);
void create_db_message(char *dest, msg_components *comps);

#endif

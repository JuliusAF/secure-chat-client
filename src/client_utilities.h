#ifndef CLIENT_UTILITIES_H
#define CLIENT_UTILITIES_H

#include <stdbool.h>
#include "cryptography.h"
#include "parser.h"

#define DATE_FORMAT "%Y-%m-%d %H:%M:%S"

typedef struct message_format {
  char date[60];
  char sender[USERNAME_MAX+1];
  char recipient[USERNAME_MAX+1];
  char message[MESSAGE_MAX+1];
} format_msg_t;

typedef struct user_info {
  bool is_logged;
  char username[USERNAME_MAX+1];
  unsigned char masterkey[MASTER_KEY_LEN+1];
  key_pair_t *rsa_keys;
} user_t;

user_t *initialize_user_info();
int read_stdin(char *buffer, int size);
int create_date_string(char *date, time_t t);
int create_formatted_msg(char *msg, command_t *n, user_t *u);
void handle_user_input(command_t *n, user_t *u);
void print_parse_error(command_t *n);
void print_error(char *s);
void handle_server_output(void);

#endif

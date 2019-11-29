#ifndef CLIENT_UTILITIES_H
#define CLIENT_UTILITIES_H

#include <stdbool.h>
#include <openssl/ssl.h>
#include "cryptography.h"
#include "network.h"
#include "parser.h"

#define DATE_FORMAT "%Y-%m-%d %H:%M:%S"


/* holds all relevant user information on the client's side */
typedef struct user_info {
  bool is_logged;
  SSL *ssl;
  int connfd;
  char username[USERNAME_MAX+1];
  unsigned char masterkey[MASTER_KEY_LEN+1];
  keypair_t *rsa_keys;
} user_t;

/* saves the state when a login or register request is made*/
typedef struct login_request {
  bool is_request_active;
  char username[USERNAME_MAX+1];
  unsigned char masterkey[MASTER_KEY_LEN+1];
} request_t;

user_t *initialize_user_info(SSL *ssl, int connfd);
request_t *initialize_request(void);
int read_stdin(char *buffer, int size);

/* these functions deal with input from the user through stdin and
sending any necessary data to the server */
int create_date_string(char *date, time_t t);
int create_formatted_msg(char *msg, command_t *n, user_t *u);
void sign_client_packet(packet_t *p, user_t *u);
void handle_user_input(command_t *n, user_t *u, request_t *r);
void handle_user_register(command_t *node, user_t *user, request_t *request);
void handle_user_login(command_t *node, user_t *user, request_t *request);
void handle_user_users(command_t *node, user_t *user);
void print_error(char *s);

/* the functions handle packets coming from the server over the socket */
void handle_server_input(server_parsed_t *p, user_t *u, request_t *r);
void handle_server_log_pass(server_parsed_t *p, user_t *u, request_t *r);
void handle_server_log_fail(server_parsed_t *p, user_t *u, request_t *r);

#endif

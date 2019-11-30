#ifndef SERVER_UTILITIES_H
#define SERVER_UTILITIES_H

#include <stdbool.h>
#include <openssl/ssl.h>
#include "parse_client_input.h"
#include "parse_user_input.h"

#define MAX_CLIENTS 30
/* The server and workers communicate over the pipes.
The communication between them, however, is very simple and
there is no need for elaborate messages. The workers tell the server
if their connection ended with "C" and the worker tells the server,
and vice versa, if the database has updated.*/
#define PIPE_MSG_UPDATE "U"
#define PIPE_MSG_CLOSE "C"
#define PIPE_MSG_LEN 1

/* stores all necessary information of a client when they are logged in */
typedef struct client_info {
  int connfd;
  SSL *ssl;
  bool is_logged;
  char username[USERNAME_MAX+1];
  unsigned int publen;
  char *pubkey;
  signed long long last_updated;
} client_t;

void worker(int connfd, int from_parent[2], int to_parent[2]);
bool is_client_sig_good(packet_t *p, client_t *c);

/* these functions handle parsed packets from the client */
void handle_client_input(client_parsed_t *p, client_t *client_info, int pipefd);
void handle_client_login(client_parsed_t *p, client_t *client_info);
void handle_client_users(client_parsed_t *p, client_t *client_info);
void handle_client_pubmsg(client_parsed_t *p, client_t *client_info, int pipefd);

/* this function handles when the databse is update with a message */
void handle_db_msg_update(client_t *client_info);

#endif

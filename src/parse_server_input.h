#ifndef PARSE_SERVER_INPUT_H
#define PARSE_SERVER_INPUT_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "network.h"

typedef struct parsed_server_input {
  uint16_t id;

  union {
    /* on a successful login or register, the server sends the client the IV
    used to AES encrypt an RSA pair, the size of the encrypted data and the
    encrypted RSA pair */
    struct {
      unsigned char *iv;
      unsigned int encrypt_sz;
      unsigned char *encrypted_keys;
    } user_details;
    /* when an error is sent from server to client, the packet contains
    only an error message in its payload.*/
    char *error_message;
    /* a /users response contains a single string that contains every user
    currently logged in, delimited with a space */
    char *users;
    /* Both public and private messages are similarly structured as packets. As such,
    they will share the same struct. Private messages simple have more fields to them.
    A public message contains the signature of the original message, the public
    key of the user that sent it, and the actual message. The hash of the original payload,
    that is the hash of the packet after the signature (length and actual signature) is
    also saved. This hash will be used to verify that the client who claims they send the
    message actually did so */
    struct {
      /* fields shared by both types of messages */
      unsigned int siglen;
      unsigned char *sig;
      unsigned char *hashed_payload;
      unsigned int publen;
      char *pubkey;
      unsigned int msglen;
      unsigned char *message;
      /* fields for private messages */
      char *recipient;
      unsigned char *iv;
      unsigned int s_symkeylen;
      unsigned char *s_symkey;
      unsigned int r_symkeylen;
      unsigned char *r_symkey;
    } messages;
    /* contains the public key asked for and the message(encrypted) that
    required that public key */
    struct {
      unsigned int keylen;
      char *key;
      char *username;
      unsigned char *iv;
      unsigned int encrypt_sz;
      unsigned char *encrypted_msg;
    } pubkey_rqst;
  };
} server_parsed_t;

typedef struct packet_to_send packet_t;

/* functions for parsing packets sent from server to client*/

server_parsed_t *parse_server_input(packet_t *p);
int parse_server_users(packet_t *packet, server_parsed_t *parsed);
int parse_server_userinfo(packet_t *packet, server_parsed_t *parsed);
int parse_server_msg(packet_t *packet, server_parsed_t *parsed);
int parse_server_pubkey_rqst(packet_t *packet, server_parsed_t *parsed);
int parse_server_error(packet_t *packet, server_parsed_t *parsed);
void initialize_server_parsed(server_parsed_t *p);
bool is_server_parsed_legal(server_parsed_t *p);
void free_server_parsed(server_parsed_t *p);

#endif

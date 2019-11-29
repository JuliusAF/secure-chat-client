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
  };
} server_parsed_t;

typedef struct packet_to_send packet_t;

/* functions for parsing packets sent from server to client*/

server_parsed_t *parse_server_input(packet_t *p);
bool is_server_parsed_legal(server_parsed_t *p);
int parse_server_userinfo(packet_t *packet, server_parsed_t *parsed);
int parse_server_error(packet_t *packet, server_parsed_t *parsed);
void initialize_server_parsed(server_parsed_t *p);
bool is_server_parsed_legal(server_parsed_t *p);
void free_server_parsed(server_parsed_t *p);

#endif

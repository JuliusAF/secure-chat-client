#ifndef PARSE_CLIENT_INPUT_H
#define PARSE_CLIENT_INPUT_H

#include <stdbool.h>
#include "network.h"
#include "parse_user_input.h"

typedef struct parsed_client_input {
  uint16_t id;

  union {
    /* when sending a registration packet to the server, the following fields
    must be sent */
    struct {
      char *username;
      unsigned char *hash_password;
      unsigned int publen;
      char *pubkey;
      unsigned char *iv;
      unsigned int encrypt_sz;
      unsigned char *encrypted_keys;
    } reg_packet;
    /* a login request packet contains the username and hashed password
    of the person logging in*/
    struct {
      char *username;
      unsigned char *hash_password;
    } log_packet;
  };

} client_parsed_t;

typedef struct packet_to_send packet_t;

/* functions for parsing packets received server side from the client */
client_parsed_t *parse_client_input(packet_t *p);
int parse_client_register(packet_t *packet, client_parsed_t *parsed);
int parse_client_login(packet_t *packet, client_parsed_t *parsed);
int parse_client_users(packet_t *packet, client_parsed_t *parsed);
void initialize_client_parsed(client_parsed_t *p) ;
bool is_client_parsed_legal(client_parsed_t *p);
void free_client_parsed(client_parsed_t *p);

#endif

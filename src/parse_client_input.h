#ifndef PARSE_CLIENT_INPUT_H
#define PARSE_CLIENT_INPUT_H

#include <stdbool.h>
#include "network.h"
#include "parse_user_input.h"

/* holds the parsed input from the client based on what type of message was transmitted */
typedef struct parsed_client_input {
  uint16_t id;

  union {
    /* when sending a registration packet to the server, the following fields
    must be received */
    struct {
      char *username;
      unsigned char *hash_password;
      unsigned int certlen;
      char *cert;
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
    /* a public message contains the actual message, as well as the signature
    that signed the packet. The certificate and sender is discarded as the server already has
    this information */
    struct {
      unsigned int siglen;
      unsigned char *sig;
      unsigned int msg_sz;
      char *message;
    } pubmsg_packet;
    /* a request for another users certificate also includes the sender, encrypted message and iv to make
    responding to the return message on the client side easier */
    struct {
      unsigned int siglen;
      unsigned char *sig;
      char *username;
      unsigned int original_sz;
      unsigned char *original;
    } pubkey_rqst;
    /* a private message contains the same items as a public message, as well as
    the recipient name, an initialization vector, and two symmetric keys */
    struct {
      unsigned int siglen;
      unsigned char *sig;
      unsigned int msg_sz;
      unsigned char *message;
      char *recipient;
      unsigned char *iv;
      unsigned int s_symkeylen;
      unsigned char *s_symkey;
      unsigned int r_symkeylen;
      unsigned char *r_symkey;
    } privmsg_packet;
  };

} client_parsed_t;

/* forward declaration for packet */
typedef struct packet_to_send packet_t;

/* functions for parsing packets received server side from the client */
client_parsed_t *parse_client_input(packet_t *p);
int parse_client_register(packet_t *packet, client_parsed_t *parsed);
int parse_client_login(packet_t *packet, client_parsed_t *parsed);
int parse_client_users(packet_t *packet, client_parsed_t *parsed);
int parse_client_pubmsg(packet_t *packet, client_parsed_t *parsed);
int parse_client_pubkey_rqst(packet_t *packet, client_parsed_t *parsed);
int parse_client_privmsg(packet_t *packet, client_parsed_t *parsed);
void initialize_client_parsed(client_parsed_t *p);
bool is_client_parsed_legal(client_parsed_t *p);
void free_client_parsed(client_parsed_t *p);

#endif

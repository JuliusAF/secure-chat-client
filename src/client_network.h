#ifndef CLIENT_NETWORK_H
#define CLIENT_NETWORK_H

#include "network.h"
#include "cryptography.h"
#include "client_utilities.h"
#include "parse_user_input.h"
#include "parse_server_input.h"

/* functions to handle the network aspect of assimilating register packet
to send it over to the server */
unsigned char *serialize_keypair(keypair_t *k, int size);
keypair_t *deserialize_keypair(unsigned char *serialized, int size);
unsigned char *serialize_register(command_t *n, unsigned char *masterkey, keypair_t *k, int *size);
packet_t *gen_c_register_packet(command_t *n, request_t *r);

/* functions to handle the network aspect of creating a login request
packet to send to the server */
unsigned char *serialize_login(command_t *n);
packet_t *gen_c_login_packet(command_t *n);

/* functions to handle a users request */
packet_t *gen_c_users_packet(command_t *n);

/* functions to handle a public message */
unsigned char *serialize_pubmsg(char *message, user_t *u, unsigned int payload_sz);
packet_t *gen_c_pubmsg_packet(command_t *n, user_t *u);

/* functions to handle a private message request */
unsigned char *serialize_pubkey_rqst(command_t *n, user_t *u, unsigned int *payload_sz);
packet_t *gen_c_pubkey_rqst_packet(command_t *n, user_t *u);

/* functions to handle the construction of an actual private message payload */
unsigned char *serialize_privmsg(server_parsed_t *p, user_t *u, unsigned int *payload_sz);
packet_t *gen_c_privmsg_packet(server_parsed_t *p, user_t *u);

/* these functions create a formatted message if the command is a public
message of a private message */
int create_date_string(char *date, time_t t);
int create_formatted_msg(char *msg, command_t *n, user_t *u);

#endif

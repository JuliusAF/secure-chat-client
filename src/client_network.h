#ifndef CLIENT_NETWORK_H
#define CLIENT_NETWORK_H

#include "network.h"
#include "parser.h"
#include "cryptography.h"
#include "client_utilities.h"

/* functions to handle the network aspect of assimilating register packet
to send it over to the server */
unsigned char *serialize_keypair(keypair_t *k, int size);
keypair_t *deserialize_keypair(unsigned char *serialized, int size);
unsigned char *serialize_register(command_t *n, unsigned char *masterkey, keypair_t *k, int *size);
packet_t *gen_c_register_packet(command_t *n, request_t *r);

#endif

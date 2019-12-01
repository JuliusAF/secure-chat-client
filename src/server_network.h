#ifndef SERVER_NETWORK_H
#define SERVER_NETWORK_H

#include "network.h"
#include "database.h"
#include "parse_client_input.h"

packet_t *gen_s_error_packet(uint16_t id, char *err_msg);
packet_t *gen_s_userinfo_packet(fetched_userinfo_t *f, uint16_t id);
packet_t *gen_s_users_packet(char *users);
/* these functions handle the network aspect of the server sending the client
a public or private message */
unsigned char *serialize_message(msg_components_t *m, unsigned int payload_sz);
packet_t *gen_s_msg_packet(msg_components_t *m);
packet_t *gen_s_msgcount_packet(unsigned int count);
unsigned char *serialize_pubkey_request(client_parsed_t *p, char *key, unsigned int len, unsigned int payload_sz);
packet_t *gen_s_pubkey_rqst_packet(client_parsed_t *p, char *key, unsigned int len);

#endif

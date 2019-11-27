#ifndef SERVER_NETWORK_H
#define SERVER_NETWORK_H

#include "network.h"
#include "database.h"

packet_t *gen_s_error_packet(uint16_t id, char *err_msg);
packet_t *gen_s_userinfo_packet(fetched_userinfo_t *f, uint16_t id);

#endif

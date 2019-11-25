#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include "parser.h"

#define MAX_PACKET_SIZE 1024
/* define the id codes for packets from clients to server */
#define C_MSG_PARSED 1001
/* defines the id codes for packets from server to clients*/
#define S_MSG_PAYLOAD 2001
#define S_MSG_ERROR 2002
#define S_MSG_USERS 2003
/* defines fixed size of header*/
#define HEADER_SIZE sizeof(uint32_t) + sizeof(uint16_t)

typedef struct packet_header {
  uint32_t pckt_sz;
  uint16_t pckt_id;
} packet_hdr_t;

typedef struct packet {
  packet_hdr_t *header;
  char *payload;
} packet_t;

int create_server_socket(unsigned short port);
int client_connect(const char *hostname, unsigned short port);
int accept_connection(int serverfd);

packet_t *serialize_command_struct(command_t *n, packet_hdr_t *h);
command_t *deserialize_command_struct(char *packet);
char *create_packet(packet_t *t);

#endif

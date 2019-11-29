#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <openssl/ssl.h>
#include "cryptography.h"

/* defines fixed size of header*/
#define HEADER_SIZE (sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + MAX_SIG_SZ)
/* The limit here is reasonably higher than what is needed, but
is defined to ensure a benchmark for packet size */
#define MAX_PACKET_SIZE 4096
#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - HEADER_SIZE)
/* a login request has a fixed size defined here */
#define LOGIN_REQUEST_SIZE USERNAME_MAX + SHA256_DIGEST_LENGTH
/* defines the payload for a user request. Used to create signature and is
a constant as a user command requires no information from the client */
#define USERS_MSG_PAYLOAD "client users request"
#define USERS_MSG_SIZE 20

/* define the id codes for packets from clients to server */
#define C_MSG_EXIT 1001
#define C_MSG_LOGIN 1002
#define C_MSG_REGISTER 1003
#define C_MSG_PRIVMSG 1004
#define C_MSG_PUBMSG 1005
#define C_MSG_USERS 1006

#define C_META_PUBKEY_RQST 1101



/* defines the id codes for packets from server to clients*/
#define S_MSG_PUBMSG 2001
#define S_MSG_PRIVMSG 2002
#define S_MSG_USERS 2003
#define S_MSG_GENERIC_ERR 2004

#define S_META_LOGIN_PASS 2101
#define S_META_LOGIN_FAIL 2102
#define S_META_REGISTER_PASS 2103
#define S_META_REGISTER_FAIL 2104

/* maximum size for rsa signature*/
#define MAX_SIG_SZ 256

typedef struct packet_header {
  uint32_t pckt_sz;
  uint16_t pckt_id;
  uint32_t siglen;
  unsigned char sig[MAX_SIG_SZ];
} packet_hdr_t;

typedef struct packet_to_send {
  packet_hdr_t *header;
  unsigned char *payload;
} packet_t;

int create_server_socket(unsigned short port);
int client_connect(const char *hostname, unsigned short port);
int accept_connection(int serverfd);

int send_packet_over_socket(SSL *ssl, int fd, packet_t *p);
int read_packet_from_socket(SSL *ssl, int fd, unsigned char *buffer);
bool is_packet_legal(packet_t *p);
packet_hdr_t *initialize_header(uint16_t id, uint32_t sz);
packet_t *pack_packet(packet_hdr_t *header, unsigned char *payload);
unsigned char *serialize_packet(packet_t *p);
packet_t *deserialize_packet(unsigned char *buffer, int size);
void free_packet(packet_t *p);

#endif

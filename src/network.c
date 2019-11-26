#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include "ssl-nonblock.h"
#include "safe_wrappers.h"
#include "parser.h"
#include "network.h"

int create_server_socket(unsigned short port) {
  int fd, r;
  struct sockaddr_in addr;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("failed to create server socket");
    exit(EXIT_FAILURE);
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  r = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
  if (r != 0) {
    perror("failed to bind server socket");
    exit(EXIT_FAILURE);
  }

  r = listen(fd, 0);
  if (r != 0) {
    perror("failed to set server socket to listening");
    exit(EXIT_FAILURE);
  }

  return fd;
}

static int lookup_host_ipv4(const char *hostname, struct in_addr *addr) {
  struct hostent *host;

  host = gethostbyname(hostname);
  while (host) {
    if(host->h_addrtype == AF_INET &&
      host->h_addr_list &&
      host->h_addr_list[0]) {
      memcpy(addr, host->h_addr_list[0], sizeof(*addr));
      return 0;
    }
    host = gethostent();
  }

  return -1;
}

int client_connect(const char *hostname, unsigned short port) {
  struct sockaddr_in addr;
  int fd, r;

  r = lookup_host_ipv4(hostname, &addr.sin_addr);
  if (r != 0) {
    perror("failed to find host");
    exit(EXIT_FAILURE);
  }

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("failed to create client socket");
    exit(EXIT_FAILURE);
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  r = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
  if (r != 0) {
    perror("failed to connect client socket");
    exit(EXIT_FAILURE);
  }
  return fd;
}

int accept_connection(int serverfd) {
  int connfd;

  connfd = accept(serverfd, NULL, NULL);
  if (connfd < 0) {
    perror("failed to accept incoming connection");
    return -1;
  }
  return connfd;
}

/* Reads a single packet from an ssl socket. It does not buffer what is
in read*/
int read_packet_from_socket(SSL *ssl, int fd, unsigned char *buffer) {
  int bytes_read, total = 0;
  uint32_t data_size;

  /* continues to read from socket until the complete header is read*/
  while (total < (int) HEADER_SIZE) {
    bytes_read = ssl_block_read(ssl, fd, buffer+total, HEADER_SIZE-total);
    if (bytes_read < 1)
      return bytes_read;

    total += bytes_read;
  }
  /* find size of data payload*/
  memcpy(&data_size, buffer, sizeof(uint32_t));
  if (data_size > MAX_PAYLOAD_SIZE)
    return -1;

  /* continues to read from socket until the complete payload is read*/
  while (total < (int) (HEADER_SIZE+data_size)) {
    bytes_read = ssl_block_read(ssl, fd, buffer+total, HEADER_SIZE-total);
    if (bytes_read < 1)
      return bytes_read;

    total += bytes_read;
  }
  return total;
}

/* creates a packet_t struct from a packet header and payload*/
packet_t *pack_packet(packet_hdr_t *header, unsigned char *payload) {
  packet_t *p;

  if (header == NULL || payload == NULL)
    return NULL;

  p = (packet_t *) safe_malloc(sizeof(packet_t));
  if (p == NULL)
    return NULL;

  p->header = header;
  p->payload = payload;

  return p;
}

/* converts a packet struct in a byte stream of type unsigned char.
it automatically frees the packet passed to it*/
unsigned char *serialize_packet(packet_t *p) {
  int size, index = 0;
  unsigned char *serialized, *data;
  packet_hdr_t *hdr;

  if (p == NULL)
    return NULL;

  hdr = p->header;
  data = p->payload;
  size = (int) (HEADER_SIZE+hdr->pckt_sz);
  serialized = (unsigned char *) safe_malloc(sizeof(unsigned char) * size);
  if (serialized == NULL)
    return NULL;

  memcpy(serialized, &hdr->pckt_sz, sizeof(uint32_t));
  index += (int) sizeof(uint32_t);
  memcpy(serialized+index, &hdr->pckt_id, sizeof(uint16_t));
  index += (int) sizeof(uint16_t);
  memcpy(serialized+index, hdr->sig, MAX_SIG_SZ);
  index += MAX_SIG_SZ;
  memcpy(serialized+index, data, hdr->pckt_sz);

  free_packet(p);
  return serialized;
}

/* deconstructs a character buffer containing a packet into a packet struct
which will be used for further processing later*/
packet_t *unpack_packet(unsigned char *buffer, int size) {
  int index = 0;
  packet_t *packet;
  packet_hdr_t *header;
  unsigned char *payload;

  if (buffer == NULL || size == 0
    || size > MAX_PACKET_SIZE)
    return NULL;

  packet = (packet_t *) safe_malloc(sizeof(packet_t));
  header = (packet_hdr_t *) safe_malloc(sizeof(packet_hdr_t));
  payload = (unsigned char *) safe_malloc(sizeof(unsigned char) * MAX_PAYLOAD_SIZE);

  memcpy(&header->pckt_sz, buffer, sizeof(uint32_t));
  if (size < (int) (header->pckt_sz+HEADER_SIZE)) {
    free(packet);
    free(header);
    free(payload);

    return NULL;
  }

  index += sizeof(uint32_t);
  memcpy(&header->pckt_id, buffer+index, sizeof(uint16_t));
  index += sizeof(uint16_t);
  memcpy(header->sig, buffer+index, MAX_SIG_SZ);
  index += MAX_SIG_SZ;
  memcpy(payload, buffer+index, header->pckt_sz);

  packet->header = header;
  packet->payload = payload;
  return packet;
}

void free_packet(packet_t *p) {
  if (p == NULL)
    return;

  free(p->header);
  free(p->payload);
  free(p);
}

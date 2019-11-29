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

bool is_packet_legal(packet_t *p) {
  return (p != NULL && p->header != NULL && p->payload != NULL);
}

/* serializes a packet and sends it over the network */
int send_packet_over_socket(SSL *ssl, int fd, packet_t *p) {
  int bytes_written, total = 0, size;
  unsigned char *serialized;

  if (!is_packet_legal(p)) {
    free_packet(p);
    return -1;
  }

  size = (int) (p->header->pckt_sz+HEADER_SIZE);
  serialized = serialize_packet(p);
  if (serialized == NULL)
    return -1;
  //printf("printinf serialized\n");
  //write(1, serialized, size);
  //printf("\n");
  /* write to socket until the entire packet has been sent */
  while (size > 0) {
    bytes_written = ssl_block_write(ssl, fd, serialized+total, size);
    if (bytes_written == -1) {
      perror("failed to write over socket");
      free(serialized);
      return -1;
    }
    size -= bytes_written;
  }

  free(serialized);
  return 1;
}

/* Reads a single packet from an ssl socket. It does not buffer what is
in read*/
int read_packet_from_socket(SSL *ssl, int fd, unsigned char *buffer) {
  int bytes_read, total = 0;
  unsigned int packet_sz;
  uint32_t data_size;

  /* continues to read from socket until the complete header is read*/
  while (total < (int) HEADER_SIZE) {
    bytes_read = ssl_block_read(ssl, fd, buffer+total, HEADER_SIZE-total);
    if (bytes_read < 0){
      fprintf(stderr, "failed to read header bytes\n");
      perror("header read");
      return bytes_read;
    }
    else if (bytes_read == 0) {
      return 0;
    }

    total += bytes_read;
  }
  /* find size of data payload*/
  memcpy(&data_size, buffer, sizeof(uint32_t));
  if (data_size > MAX_PAYLOAD_SIZE)
    return -1;
  packet_sz = HEADER_SIZE+data_size;

  /* continues to read from socket until the complete payload is read*/
  while (total < (int) (HEADER_SIZE+data_size)) {
    bytes_read = ssl_block_read(ssl, fd, buffer+total, packet_sz-total);
    if (bytes_read < 0){
      fprintf(stderr, "failed to read data bytes\n");
      perror("data read");
      return bytes_read;
    }
    else if (bytes_read == 0) {
      return 0;
    }

    total += bytes_read;
  }
  /* ensures that the amount of data the packet claims to have is equal to the
  number of bytes read */
  if (total != (int) packet_sz) {
    fprintf(stderr, "Failed to read proper amount of bytes\n");
    return -1;
  }
  return total;
}

/* creates and initializes a packet header using the input provided.
returns a pointer to the structure that is later free with free_packet() */
packet_hdr_t *initialize_header(uint16_t id, uint32_t sz) {
  packet_hdr_t *header;

  header = safe_malloc(sizeof(packet_hdr_t));
  if (header == NULL)
    return NULL;

  header->pckt_id = id;
  header->pckt_sz = sz;
  header->siglen = 0;
  memset(header->sig, '\0', MAX_SIG_SZ);

  return header;
}

/* creates a packet_t struct from a packet header and payload*/
packet_t *pack_packet(packet_hdr_t *header, unsigned char *payload) {
  packet_t *p;

  if (header == NULL || payload == NULL)
    return NULL;

  p = safe_malloc(sizeof(packet_t));
  if (p == NULL)
    return NULL;

  p->header = header;
  p->payload = payload;

  return p;
}

/* converts a packet struct into a byte stream of type unsigned char.
it automatically frees the packet passed to it*/
unsigned char *serialize_packet(packet_t *p) {
  int size, index = 0;
  unsigned char *serialized, *data;
  packet_hdr_t *hdr;

  if (p == NULL)
    return NULL;
  if (p->header == NULL || p->payload == NULL) {
    free_packet(p);
    return NULL;
  }

  hdr = p->header;
  data = p->payload;
  size = (int) (HEADER_SIZE+hdr->pckt_sz);
  serialized = safe_malloc(sizeof(unsigned char) * size);
  if (serialized == NULL){
    free_packet(p);
    return NULL;
  }

  memcpy(serialized, &hdr->pckt_sz, sizeof(uint32_t));
  index += (int) sizeof(uint32_t);
  memcpy(serialized+index, &hdr->pckt_id, sizeof(uint16_t));
  index += (int) sizeof(uint16_t);
  memcpy(serialized+index, &hdr->siglen, sizeof(uint32_t));
  index += (int) sizeof(uint32_t);
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

  if (buffer == NULL || size < 1
    || size > MAX_PACKET_SIZE)
    return NULL;

  packet = safe_malloc(sizeof(packet_t));
  if (packet == NULL)
    return NULL;
  header = safe_malloc(sizeof(packet_hdr_t));
  if (header == NULL) {
    free(packet);
    return NULL;
  }

  memcpy(&header->pckt_sz, buffer, sizeof(uint32_t));
  if (size != (int) (header->pckt_sz+HEADER_SIZE)) {
    fprintf(stderr, "unpack packet failed size check\n");
    free(packet);
    free(header);
    return NULL;
  }

  payload = safe_malloc(sizeof(unsigned char) * header->pckt_sz);
  if (payload == NULL) {
    free(packet);
    free(header);
    return NULL;
  }

  index += sizeof(uint32_t);
  memcpy(&header->pckt_id, buffer+index, sizeof(uint16_t));
  index += sizeof(uint16_t);
  memcpy(&header->siglen, buffer+index, sizeof(uint32_t));
  index += sizeof(uint32_t);
  memcpy(header->sig, buffer+index, MAX_SIG_SZ);
  index += MAX_SIG_SZ;
  memcpy(payload, buffer+index, header->pckt_sz);

  if (header->siglen > MAX_SIG_SZ) {
    fprintf(stderr, "signature size is larger than is possible \n");
    free(packet);
    free(header);
    return NULL;
  }

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

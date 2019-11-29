#include "network.h"
#include "safe_wrappers.h"
#include "database.h"
#include "server_network.h"

/* creates an error packet. That is a packet that is transmitted to make
the client aware of some error. It takes as input the id of the packet
and the error message (null terminated) */
packet_t *gen_s_error_packet(uint16_t id, char *err_msg) {
  unsigned int payload_sz;
  packet_hdr_t *header = NULL;
  unsigned char *payload = NULL;

  if (err_msg == NULL || strlen(err_msg) == 0)
    return NULL;

  payload_sz = strlen(err_msg);
  payload = safe_malloc(sizeof(unsigned char) * payload_sz);
  if (payload == NULL)
    return NULL;

  header = initialize_header(id, payload_sz);
  if (header == NULL) {
    free(payload);
    return NULL;
  }

  memcpy(payload, err_msg, header->pckt_sz);

  return pack_packet(header, payload);
}

/* this function generates a packet with the user info that is sent
to the client on a successful registration or login. It takes an id
as input because the id for a successful login or register is different and
must be specified */
packet_t *gen_s_userinfo_packet(fetched_userinfo_t *f, uint16_t id) {
  unsigned char *payload = NULL, *tmp = NULL;
  packet_hdr_t *header = NULL;

  if (!is_fetched_userinfo_legal(f))
    return NULL;

  const unsigned int payload_sz = IV_SIZE + sizeof(unsigned int) + f->encrypt_sz;
  if (payload_sz > MAX_PAYLOAD_SIZE) {
    fprintf(stderr, "register packet too big: %d\n", payload_sz);
    return NULL;
  }

  payload = safe_malloc(sizeof(unsigned char) * payload_sz);
  header = initialize_header(id, payload_sz);
  if (payload == NULL || header == NULL) {
    free(header);
    free(payload);
    return NULL;
  }

  tmp = payload;
  memcpy(tmp, f->iv, IV_SIZE);
  tmp += IV_SIZE;
  memcpy(tmp, &f->encrypt_sz, sizeof(unsigned int));
  tmp +=sizeof(unsigned int);
  memcpy(tmp, f->encrypted_keys, f->encrypt_sz);

  return pack_packet(header, payload);
}

/* This function creates a packet that holds the list of users currently logged in,
delimited with spaces */

packet_t *gen_s_users_packet(char *users) {
  unsigned char *payload = NULL;
  packet_hdr_t *header = NULL;

  header = initialize_header(S_MSG_USERS, strlen(users));
  payload = safe_malloc(sizeof(unsigned char) * strlen(users));
  if (payload == NULL || header == NULL) {
    free(header);
    free(payload);
    return NULL;
  }

  memcpy(payload, users, strlen(users));

  return pack_packet(header, payload);
}

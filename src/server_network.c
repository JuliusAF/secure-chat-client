#include "network.h"
#include "safe_wrappers.h"
#include "database.h"
#include "server_network.h"

packet_t *gen_s_error_packet(uint16_t id, char *err_msg) {
  unsigned int payload_sz;
  packet_hdr_t *header = NULL;
  unsigned char *payload = NULL;

  if (err_msg == NULL || strlen(err_msg) == 0)
    return NULL;

  payload_sz = strlen(err_msg);
  payload = (unsigned char *) safe_malloc(sizeof(unsigned char) * payload_sz);
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

  payload = (unsigned char *) safe_malloc(sizeof(unsigned char) * payload_sz);
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

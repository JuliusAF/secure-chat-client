#include "network.h"
#include "safe_wrappers.h"
#include "database.h"

packet_t *gen_s_error_packet(uint16_t id, char *err_msg) {
  int payload_sz;
  packet_hdr_t *header = NULL;
  unsigned char *payload = NULL;

  if (err_msg == NULL || strlen(err_msg) == 0)
    return NULL;

  payload_sz = strlen(err_msg);
  header = (packet_hdr_t *) safe_malloc(sizeof(packet_hdr_t));
  payload = (unsigned char *) safe_malloc(sizeof(unsigned char) * payload_sz);
  if (header == NULL || payload == NULL) {
    free(header);
    free(payload);
    return NULL;
  }

  header->pckt_id = (uint32_t) id;
  header->pckt_sz = payload_sz;
  memset(header->sig, '\0', MAX_SIG_SZ);
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
  header = (packet_hdr_t *) safe_malloc(sizeof(packet_hdr_t));
  if (payload == NULL || header == NULL) {
    free(header);
    free(payload);
    return NULL;
  }
  header->pckt_id = id;
  header->pckt_sz = payload_sz;
  memset(header->sig, '\0', MAX_SIG_SZ);

  tmp = payload;
  memcpy(tmp, f->iv, IV_SIZE);
  tmp += IV_SIZE;
  memcpy(tmp, &f->encrypt_sz, sizeof(unsigned int));
  tmp +=sizeof(unsigned int);
  memcpy(tmp, f->encrypted_keys, f->encrypt_sz);

  return pack_packet(header, payload);
}

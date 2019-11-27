#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "safe_wrappers.h"
#include "cryptography.h"
#include "network.h"
#include "parser.h"
#include "client_network.h"
#include "client_utilities.h"

/* turns a keypair struct into a byte stream. This will be later encrypted
using AES*/
unsigned char *serialize_keypair(keypair_t *k, int size) {
  int index;
  unsigned char *serialized;

  if(!is_keypair_legal(k) || size < 0)
    return NULL;

  serialized = (unsigned char *) safe_malloc(sizeof(unsigned char) * size);
  if (serialized == NULL)
    return NULL;

  /* copy the individual fields into their respective positions*/
  memcpy(serialized, &k->privlen, sizeof(int));
  index = sizeof(int);
  memcpy(serialized+index, k->privkey, k->privlen);
  index += k->privlen;
  memcpy(serialized+index, &k->publen, sizeof(int));
  index += sizeof(int);
  memcpy(serialized+index, k->pubkey, k->publen);

  return serialized;
}

/* serializes all of the components of a register packet. This includes the username and password
of the request, as well as the created RSA key pair. The key pair will be serialized and encrypted
with the master key (function of username and password) using AES-128-CBC. The makeup
of this serialized byte array can be found in the README under protocol->register*/
unsigned char *serialize_register(command_t *n, unsigned char *masterkey, keypair_t *k, int *size) {
  bool error = false;
  int keypair_sz, payload_sz, encrypted_sz;
  unsigned char *payload = NULL, *serial_keys = NULL,
  encrypted_keys[4000], *iv = NULL, *hashed_pass = NULL, *tmp;

  if (n == NULL || n->command != COMMAND_REGISTER ||
      !is_keypair_legal(k) || size == NULL ||
      masterkey == NULL)
    return NULL;

  keypair_sz = (sizeof(int)*2) + k->privlen + k->publen;
  serial_keys = serialize_keypair(k, keypair_sz);
  if (serial_keys == NULL)
    return NULL;

  iv = create_rand_salt(IV_SIZE);
  if (iv == NULL) {
    error = true;
    goto cleanup;
  }
  encrypted_sz = apply_aes(encrypted_keys, serial_keys, keypair_sz, masterkey, iv, ENCRYPT);
  if (encrypted_sz < 0) {
    error = true;
    goto cleanup;
  }

  hashed_pass = hash_password(n->acc_details.password, strlen(n->acc_details.password), NULL, 0);
  if (hashed_pass == NULL) {
    error = true;
    goto cleanup;
  }

  payload_sz = USERNAME_MAX + SHA256_DIGEST_LENGTH + sizeof(int) + k->publen +
               IV_SIZE + sizeof(int) + encrypted_sz;
  *size = payload_sz;

  payload = (unsigned char *) safe_malloc(sizeof(unsigned char) * payload_sz);
  if (payload == NULL){
    error = true;
    goto cleanup;
  }
  memset(payload, '\0', payload_sz);
  tmp = payload;

  /* create the serialized byte array */
  memcpy(tmp, n->acc_details.username, strlen(n->acc_details.username));
  tmp += USERNAME_MAX;
  memcpy(tmp, hashed_pass, SHA256_DIGEST_LENGTH);
  tmp += SHA256_DIGEST_LENGTH;
  memcpy(tmp, &k->publen, sizeof(int));
  tmp += sizeof(int);
  memcpy(tmp, k->pubkey, k->publen);
  tmp += k->publen;
  memcpy(tmp, iv, IV_SIZE);
  tmp += IV_SIZE;
  memcpy(tmp, &encrypted_sz, sizeof(int));
  tmp += sizeof(int);
  memcpy(tmp, encrypted_keys, encrypted_sz);

  cleanup:

  free(iv);
  free(serial_keys);
  free(hashed_pass);
  if (error)
    free(payload);
  return error ? NULL : payload;
}

/* this function actually generates a packet in the form of packet_t. this will
be passed to a write function for transmission over the socket */
packet_t *gen_c_register_packet(command_t *n, request_t *r) {
  int payload_sz;
  packet_hdr_t *header;
  unsigned char *payload;
  keypair_t *keys;

  if (n == NULL || r == NULL)
    return NULL;

  header = (packet_hdr_t *) safe_malloc(sizeof(packet_hdr_t));
  if (header == NULL)
    return NULL;

  header->pckt_id = C_MSG_REGISTER;
  memset(header->sig, '\0', MAX_SIG_SZ);

  keys = create_rsa_pair();
  if (!is_keypair_legal(keys)) {
    free_keypair(keys);
    free(header);
    return NULL;
  }

  payload = serialize_register(n, r->masterkey, keys, &payload_sz);
  if (payload == NULL && payload_sz < 1) {
    free_keypair(keys);
    free(header);
    return NULL;
  }
  header->pckt_sz = payload_sz;

  free_keypair(keys);
  return pack_packet(header, payload);
}

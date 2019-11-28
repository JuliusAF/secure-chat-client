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

/* The following four functions are used during register requests from users,
as well as when the server returns a successful login attempt, thereby sending
an encrypted RSA key pair over the socket */

/* turns a keypair struct into a byte stream. This will be later encrypted
using AES
The formated of the serialization is:
- the size of the private key
- the private key
- the size of the public key
- the public key*/
unsigned char *serialize_keypair(keypair_t *k, int size) {
  int index;
  unsigned char *serialized;

  if(!is_keypair_legal(k) || size < 0)
    return NULL;

  serialized = (unsigned char *) safe_malloc(sizeof(unsigned char) * size);
  if (serialized == NULL)
    return NULL;

  /* copy the individual fields into their respective positions*/
  memcpy(serialized, &k->privlen, sizeof(unsigned int));
  index = sizeof(unsigned int);
  memcpy(serialized+index, k->privkey, k->privlen);
  index += k->privlen;
  memcpy(serialized+index, &k->publen, sizeof(unsigned int));
  index += sizeof(unsigned int);
  memcpy(serialized+index, k->pubkey, k->publen);

  return serialized;
}

/* converts a byte stream containing the key pair back into a keypair_t struct.
The format of the bytes is privlen, privkey, publen, punkey */
keypair_t *deserialize_keypair(unsigned char *serialized, int size) {
  unsigned char *tmp, *tmpend;
  keypair_t *keypair = NULL;

  if (serialized == NULL ||size < 0)
    return NULL;

  keypair = (keypair_t *) safe_malloc(sizeof(keypair_t));
  if (keypair == NULL)
    return NULL;
  keypair->privkey = NULL;
  keypair->pubkey = NULL;

  tmp = serialized;
  tmpend = tmp + size;

  memcpy(&keypair->privlen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  if ((tmp + keypair->privlen + sizeof(unsigned int)) > tmpend) {
    fprintf(stderr, "can't copy private key, would overflow \n");
    free_keypair(keypair);
    return NULL;
  }

  keypair->privkey = (char *) safe_malloc(sizeof(char) * keypair->privlen+1);
  if (keypair->privkey == NULL) {
    free_keypair(keypair);
    return NULL;
  }
  memcpy(keypair->privkey, tmp, keypair->privlen);
  tmp += keypair->privlen;
  keypair->privkey[keypair->privlen] = '\0';
  memcpy(&keypair->publen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  if ((tmp + keypair->publen) > tmpend) {
    fprintf(stderr, "can't copy public key, would overflow\n");
    free_keypair(keypair);
    return NULL;
  }

  keypair->pubkey = (char *) safe_malloc(sizeof(char) * keypair->publen+1);
  if (keypair->pubkey == NULL) {
    free_keypair(keypair);
    return NULL;
  }
  memcpy(keypair->pubkey, tmp, keypair->publen);
  keypair->pubkey[keypair->publen] = '\0';

  return keypair;
}

/* serializes all of the components of a register packet. This includes the username and hashed password
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
  printf("password from user: %ld\n", strlen(n->acc_details.password));
  if (hashed_pass == NULL) {
    error = true;
    goto cleanup;
  }
  printf("hash password on client side:\n");
  print_hex(hashed_pass, SHA256_DIGEST_LENGTH);

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

  /* the size of the payload is calculated in the following function and
  stored in the payload_sz integer */
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

/* The following two functions handle the assimilation of a login request packet */

/* */
unsigned char *serialize_login(command_t *n) {
  unsigned char *payload, *tmp, *hashed_pass;

  if (n == NULL)
    return NULL;

  hashed_pass = hash_password(n->acc_details.password, strlen(n->acc_details.password), NULL, 0);
  if (hashed_pass == NULL)
    return NULL;

  payload = (unsigned char *) safe_malloc(sizeof(unsigned char) * LOGIN_REQUEST_SIZE);
  if (payload == NULL){
    free(hashed_pass);
    return NULL;
  }
  memset(payload, '\0', LOGIN_REQUEST_SIZE);
  tmp = payload;

  memcpy(tmp, n->acc_details.username, strlen(n->acc_details.username));
  tmp += USERNAME_MAX;
  memcpy(tmp, hashed_pass, SHA256_DIGEST_LENGTH);

  free(hashed_pass);
  return payload;
}

packet_t *gen_c_login_packet(command_t *n) {
  packet_hdr_t *header;
  unsigned char *payload;

  if (n == NULL)
    return NULL;

  header = (packet_hdr_t *) safe_malloc(sizeof(packet_hdr_t));
  if (header == NULL)
    return NULL;

  header->pckt_id = C_MSG_LOGIN;
  header->pckt_sz = LOGIN_REQUEST_SIZE;
  memset(header->sig, '\0', MAX_SIG_SZ);

  payload = serialize_login(n);
  if (payload == NULL) {
    free(header);
    return NULL;
  }

  return pack_packet(header, payload);
}

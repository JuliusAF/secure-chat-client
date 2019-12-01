#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include "safe_wrappers.h"
#include "cryptography.h"
#include "network.h"
#include "client_network.h"
#include "client_utilities.h"
#include "parse_user_input.h"

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

  serialized = safe_malloc(size * sizeof *serialized);
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

  keypair = safe_malloc(sizeof *keypair);
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

  keypair->privkey = safe_malloc(keypair->privlen+1 * sizeof *keypair->privkey);
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

  keypair->pubkey = safe_malloc(keypair->publen+1 * sizeof *keypair->pubkey);
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
  encrypted_keys[8000], *iv = NULL, *hashed_pass = NULL, *tmp;

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

  payload = safe_malloc(payload_sz * sizeof *payload);
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
  packet_hdr_t *header = NULL;
  unsigned char *payload = NULL;
  keypair_t *keys = NULL;

  if (n == NULL || r == NULL)
    return NULL;

  keys = create_rsa_pair();
  if (!is_keypair_legal(keys)) {
    free_keypair(keys);
    return NULL;
  }

  /* the size of the payload is calculated in the following function and
  stored in the payload_sz integer */
  payload = serialize_register(n, r->masterkey, keys, &payload_sz);
  if (payload == NULL && payload_sz < 1) {
    free_keypair(keys);
    return NULL;
  }

  header = initialize_header(C_MSG_REGISTER, payload_sz);
  if (header == NULL) {
    free_keypair(keys);
    free(payload);
    return NULL;
  }

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

  payload = safe_malloc(LOGIN_REQUEST_SIZE * sizeof *payload);
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

/* creates the actual packet for a login request. The payload of the packet
is created in serialize_login(), which turns the necessary fields into a byte
array */
packet_t *gen_c_login_packet(command_t *n) {
  packet_hdr_t *header;
  unsigned char *payload;

  if (n == NULL)
    return NULL;

  header = initialize_header(C_MSG_LOGIN, LOGIN_REQUEST_SIZE);
  if (header == NULL)
    return NULL;

  payload = serialize_login(n);
  if (payload == NULL) {
    free(header);
    return NULL;
  }

  return pack_packet(header, payload);
}

/* creates a packet for the users command. The payload contents and size is
constant, and utilized solely to sign the packet from the server side */
packet_t *gen_c_users_packet(command_t *n) {
  packet_hdr_t *header = NULL;
  unsigned char *payload = NULL;
  char tmp[USERS_MSG_SIZE+1];

  if (n == NULL || n->command != COMMAND_USERS)
    return NULL;

  payload = safe_malloc(USERS_MSG_SIZE * sizeof *payload);
  if (payload == NULL)
    return NULL;

  header = initialize_header(C_MSG_USERS, USERS_MSG_SIZE);
  if (header == NULL) {
    free(payload);
    return NULL;
  }

  strncpy(tmp, USERS_MSG_PAYLOAD, USERS_MSG_SIZE);
  memcpy(payload, tmp, USERS_MSG_SIZE);

  return pack_packet(header, payload);
}

/* a public message packet's payload is made up of 3 fields. The first is
the size of the public key, the second is the public key, the third is
the size of the message, and the fourth is the actual message.
The reason the public key is added is so that when the
packet is signed, the signature is a function of the public key, ensuring
that it's the correct one. This is done because every client that receives
this message must verify the signature with the public key anyway, so it
may as well be a necessity in the packet for verification purposes */
unsigned char *serialize_pubmsg(char *message, user_t *u, unsigned int payload_sz) {
  unsigned int s;
  unsigned char *payload = NULL, *tmp;

  if (message == NULL || u == NULL || strlen(message) == 0)
    return NULL;

  payload = safe_malloc(payload_sz * sizeof *payload);
  if (payload == NULL)
    return NULL;

  tmp = payload;
  s = strlen(message);

  memcpy(tmp, &u->rsa_keys->publen, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, u->rsa_keys->pubkey, u->rsa_keys->publen);
  tmp += u->rsa_keys->publen;
  memcpy(tmp, &s, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, message, s);

  return payload;
}

/* creates and returns a packet for a public message */
packet_t *gen_c_pubmsg_packet(command_t *n, user_t *u) {
  int ret;
  unsigned int payload_sz;
  unsigned char *payload = NULL;
  char message[500];
  packet_hdr_t *header = NULL;

  if (n == NULL || u == NULL || !is_keypair_legal(u->rsa_keys))
    return NULL;

  ret = create_formatted_msg(message, n, u);
  if (ret < 1)
    return NULL;

  payload_sz = sizeof(int) + u->rsa_keys->publen + sizeof(int) + strlen(message);
  payload = serialize_pubmsg(message, u, payload_sz);
  if (payload == NULL)
    return NULL;

  header = initialize_header(C_MSG_PUBMSG, payload_sz);
  if (header == NULL) {
    free(payload);
    return NULL;
  }

  return pack_packet(header, payload);
}

/* function to serialize a public key request. Places the size of the created payload
in the second argument. The structure is: username->iv->encrypted message */
unsigned char *serialize_pubkey_rqst(command_t *n, user_t *u, unsigned int *payload_sz) {
  const unsigned int max = 2000;
  unsigned char *payload = NULL, encrypted_msg[max], *tmp, *iv;
  char msg[max];
  int encrypted_sz, ret;

  iv = create_rand_salt(IV_SIZE);
  if (iv == NULL)
    return NULL;
  /* create the formatted message with date etc. */
  memset(msg, '\0', max);
  ret = create_formatted_msg(msg, n, u);
  if (ret < 1)
    return NULL;

  /* encrypt the message and receive message length */
  encrypted_sz = apply_aes(encrypted_msg, (unsigned char *) msg,
                 strlen(msg), u->masterkey, iv, ENCRYPT);
  if (encrypted_sz < 0) {
    free(iv);
    return NULL;
  }

  *payload_sz = USERNAME_MAX + IV_SIZE + sizeof(unsigned int) + encrypted_sz;
  payload = safe_malloc(*payload_sz * sizeof *payload);
  if (payload == NULL) {
    free(iv);
    return NULL;
  }

  tmp = payload;

  memset(payload, '\0', *payload_sz);
  memcpy(tmp, n->privmsg.username, strlen(n->privmsg.username));
  tmp += USERNAME_MAX;
  memcpy(tmp, iv, IV_SIZE);
  tmp += IV_SIZE;
  memcpy(tmp, &encrypted_sz, sizeof(int));
  tmp += sizeof(int);
  memcpy(tmp, encrypted_msg, encrypted_sz);

  free(iv);
  return payload;
}

/* this function creates a public key request. This asks the server to supply the public
key corresponding to the username mentioned. It includes the encrypted message to send
and the IV used to encrypt it so that the message can send back all of it, and the client
can process the encryption of the message for the other client without having to specifically
wait for a return packet */
packet_t *gen_c_pubkey_rqst_packet(command_t *n, user_t *u) {
  unsigned int payload_sz;
  unsigned char *payload = NULL;
  packet_hdr_t *header = NULL;

  payload = serialize_pubkey_rqst(n, u, &payload_sz);
  header = initialize_header(C_META_PUBKEY_RQST, payload_sz);
  if (payload == NULL || header == NULL) {
    free(payload);
    free(header);
    return NULL;
  }

  return pack_packet(header, payload);
}

/* handles the serialization of a private message packet. It decrypts the encrypted message
to encrypt it again with a shared symmetric key and adds that to the payload. Stores the calculated
size of the payload in the third argument */
unsigned char *serialize_privmsg(server_parsed_t *p, user_t *u, unsigned int *payload_sz) {
  const unsigned int max = 2000;
  unsigned char *payload = NULL, *iv = NULL, *symkey = NULL, *tmp,
  s_symkey[max], r_symkey[max], encrypted_msg[max], decrypted[max];
  int decrypt_sz, s_symkeylen, r_symkeylen, encryptedlen;

  /*  decrypt message from server */
  memset(decrypted, '\0', max);
  decrypt_sz = apply_aes( decrypted, p->pubkey_response.encrypted_msg,
												 p->pubkey_response.encrypt_sz, u->masterkey, p->pubkey_response.iv, DECRYPT);
	if (decrypt_sz < 0)
		return NULL;

  /* create the variables needed to encrypt the message again, this time with a symmetric key
  that both parties will receive a version of to decrypt */
  iv = create_rand_salt(IV_SIZE);
  if (iv == NULL)
    goto cleanup;

  symkey = create_rand_salt(SYMKEY_SIZE);
  if (symkey == NULL)
    goto cleanup;

  /* encrypt the message with AES-128-CBC using the created symmetric key and initialization vector */
  memset(encrypted_msg, '\0', max);
  encryptedlen = apply_aes(encrypted_msg, decrypted, decrypt_sz, symkey, iv, ENCRYPT);
  if (encryptedlen < 0)
    goto cleanup;

  /* encrypt the symmetric key with the sender's public key */
  s_symkeylen = apply_rsa_encrypt(u->rsa_keys->pubkey, u->rsa_keys->publen, SYMKEY_SIZE, symkey, s_symkey);
  if (s_symkeylen < 0)
    goto cleanup;

  /* encrypt the symmetric key with the recipient's public key */
  r_symkeylen = apply_rsa_encrypt(p->pubkey_response.key, p->pubkey_response.keylen, SYMKEY_SIZE, symkey, r_symkey);
  if (r_symkeylen < 0)
    goto cleanup;

  /* calculate the size of the packet as described in the README.md */
  *payload_sz = sizeof(unsigned int) + u->rsa_keys->publen + sizeof(unsigned int) + encryptedlen +
                USERNAME_MAX + IV_SIZE + sizeof(unsigned int) + s_symkeylen + sizeof(unsigned int) + r_symkeylen;
  payload = safe_malloc(*payload_sz * sizeof *payload);
  if (payload == NULL)
    goto cleanup;

  tmp = payload;

  memcpy(tmp, &u->rsa_keys->publen, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, u->rsa_keys->pubkey, u->rsa_keys->publen);
  tmp += u->rsa_keys->publen;
  memcpy(tmp, &encryptedlen, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, encrypted_msg, encryptedlen);
  tmp += encryptedlen;
  memset(tmp, '\0', USERNAME_MAX);
  memcpy(tmp, p->pubkey_response.username, strlen(p->pubkey_response.username));
  tmp += USERNAME_MAX;
  memcpy(tmp, iv, IV_SIZE);
  tmp += IV_SIZE;
  memcpy(tmp, &s_symkeylen, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, s_symkey, s_symkeylen);
  tmp += s_symkeylen;
  memcpy(tmp, &r_symkeylen, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, r_symkey, r_symkeylen);

  cleanup:

  free(iv);
  free(symkey);
  return payload;
}

/* creates the actual privat message that is to be stored server side and sent to
the appropriate people */
packet_t *gen_c_privmsg_packet(server_parsed_t *p, user_t *u) {
  unsigned int payload_sz;
  unsigned char *payload = NULL;
  packet_hdr_t *header = NULL;

  payload = serialize_privmsg(p, u, &payload_sz);
  header = initialize_header(C_MSG_PRIVMSG, payload_sz);
  if (header == NULL || payload == NULL) {
    free(header);
    free(payload);
    return NULL;
  }

  return pack_packet(header, payload);
}

/* creates a date string from a given time_t struct */
int create_date_string(char *date, time_t t) {
	struct tm *tmp;

	if (t < 0) {
		perror("time(null) failed");
		return -1;
	}
  /* Code taken from example supplied by the linux man page on strftime*/
  tmp = localtime(&t);

  if (tmp == NULL) {
    perror("localtime");
    return -1;
  }
  if (strftime(date, 60, DATE_FORMAT, tmp) == 0) {
    fprintf(stderr, "strftime returned 0");
    return -1;
  }
  return 1;
}

/* Takes as input a buffer, a parsed command and the user info. If the command is a private
or public message, it concatenates the fields for the corresponding message
into one string and stores it in the buffer.
Returns:
1 on success
-1 on failure */
int create_formatted_msg(char *dest, command_t *n, user_t *u) {
	char date[60];
	int ret;

	ret = create_date_string(date, time(NULL));
	if (ret < 1 || strlen(date) > 59)
		return -1;

	strcpy(dest, "");
	strcpy(dest, date);
	strncat(dest, " ", 1);
	strncat(dest, u->username, USERNAME_MAX+1);
	if(n->command == COMMAND_PRIVMSG) {
    strncat(dest, ": @", 3);
    strncat(dest, n->privmsg.username, strlen(n->privmsg.username));
    strncat(dest, " ", 1);
		strncat(dest, n->privmsg.message, strlen(n->privmsg.message));
  }
  else {
    strncat(dest, ": ", 2);
		strncat(dest, n->message, strlen(n->message));
  }

	return 1;
}

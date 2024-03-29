#include "parse_client_input.h"
#include "safe_wrappers.h"

/* These functions detail the parsing of a packet that was sent from the client
to the server */


/* function takes as input a packet and parses it into the client_parsed_t struct */
client_parsed_t *parse_client_input(packet_t *p) {
  int ret;
  unsigned int packet_size;
  client_parsed_t *parsed;

  if (!is_packet_legal(p)) {
    fprintf(stderr, "packet not legal in parse_client_input\n");
    return NULL;
  }

  packet_size = p->header->pckt_sz + HEADER_SIZE;
  if (packet_size > MAX_PACKET_SIZE) {
    fprintf(stderr, "packet size larger than max in parse_client_input\n");
    return NULL;
  }

  parsed = safe_malloc(sizeof *parsed);
  if (parsed == NULL)
    return NULL;

  parsed->id = p->header->pckt_id;
  /* sets the nodes of the parsed struct to null depending on packet id
  so that the parsed struct can always be freed without error (other than
  double freeing) */
  initialize_client_parsed(parsed);

  switch (parsed->id) {
    case C_MSG_EXIT:
      break;
    case C_MSG_LOGIN:
      ret = parse_client_login(p, parsed);
      break;
    case C_MSG_REGISTER:
      ret = parse_client_register(p, parsed);
      break;
    case C_MSG_PRIVMSG:
      ret = parse_client_privmsg(p, parsed);
      break;
    case C_MSG_PUBMSG:
      ret = parse_client_pubmsg(p, parsed);
      break;
    case C_MSG_USERS:
      ret = parse_client_users(p, parsed);
      break;
    case C_META_PUBKEY_RQST:
      ret = parse_client_pubkey_rqst(p, parsed);
      break;
    default:
      ret = -1;
      break;
  }

  if (ret < 0) {
    fprintf(stderr, "packet from client parse failed\n");
    free_client_parsed(parsed);
    return NULL;
  }
  return parsed;
}

/* parses a register request packet into the client_parsed_t struct. It deserializes
the packet whole checking for memory overflow errors etc.
Returns:
1 on success;
-1 on failure */
int parse_client_register(packet_t *packet, client_parsed_t *parsed) {
  unsigned char *payload, *tmp, *tmpend;
  unsigned int total, known_sz;

  /* checks that the packet payload size is at least as large as the known size
  requirements. (there are some fixed sizes to the packet, and some of variable size )*/
  known_sz = USERNAME_MAX + SHA256_DIGEST_LENGTH + IV_SIZE + (sizeof(unsigned int) * 2);
  if (known_sz > packet->header->pckt_sz) {
    fprintf(stderr, "register packet fails to meet minumum size requirement\n");
    return -1;
  }

  total = packet->header->pckt_sz;
  payload = packet->payload;
  tmp = payload;
  tmpend = tmp + total;

  /* allocates memory for the variables that have a constant size */
  parsed->reg_packet.username = safe_malloc(USERNAME_MAX+1 * sizeof *parsed->reg_packet.username);
  if (parsed->reg_packet.username == NULL)
    return -1;
  parsed->reg_packet.hash_password = safe_malloc(SHA256_DIGEST_LENGTH+1 * sizeof *parsed->reg_packet.hash_password);
  if (parsed->reg_packet.hash_password == NULL)
    return -1;
  parsed->reg_packet.iv = safe_malloc(IV_SIZE+1 * sizeof *parsed->reg_packet.iv);
  if (parsed->reg_packet.iv == NULL)
    return -1;

  /* traverses the payload with temporary pointer tmp. It copies the memory from payload into
  the respective variables in the parsed struct */
  memcpy(parsed->reg_packet.username, tmp, USERNAME_MAX);
  tmp += USERNAME_MAX;
  parsed->reg_packet.username[USERNAME_MAX] = '\0';
  memcpy(parsed->reg_packet.hash_password, tmp, SHA256_DIGEST_LENGTH);
  tmp += SHA256_DIGEST_LENGTH;
  parsed->reg_packet.hash_password[SHA256_DIGEST_LENGTH] = '\0';
  memcpy(&parsed->reg_packet.certlen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  /* check that the payload has enough space for at least up to the next instance of
  a variable size input */
  if (tmp + parsed->reg_packet.certlen + IV_SIZE + sizeof(unsigned int) > tmpend) {
    fprintf(stderr, "failed to copy register data 1, would overflow pointer\n");
    return -1;
  }

  parsed->reg_packet.cert = safe_malloc(parsed->reg_packet.certlen+1 * sizeof *parsed->reg_packet.cert);
  if (parsed->reg_packet.cert == NULL)
    return -1;

  memcpy(parsed->reg_packet.cert, tmp, parsed->reg_packet.certlen);
  tmp += parsed->reg_packet.certlen;
  parsed->reg_packet.cert[parsed->reg_packet.certlen] = '\0';
  memcpy(parsed->reg_packet.iv, tmp, IV_SIZE);
  tmp += IV_SIZE;
  parsed->reg_packet.iv[IV_SIZE] = '\0';
  memcpy(&parsed->reg_packet.encrypt_sz, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  /* ensure that the variable size does not cause overflow */
  if (tmp + parsed->reg_packet.encrypt_sz > tmpend) {
    fprintf(stderr, "failed to copy register data 2, would overflow pointer\n");
    return -1;
  }

  parsed->reg_packet.encrypted_keys = safe_malloc(parsed->reg_packet.encrypt_sz+1 * sizeof *parsed->reg_packet.encrypted_keys);
  if (parsed->reg_packet.encrypted_keys == NULL)
    return -1;

  memcpy(parsed->reg_packet.encrypted_keys, tmp, parsed->reg_packet.encrypt_sz);
  parsed->reg_packet.encrypted_keys[parsed->reg_packet.encrypt_sz] = '\0';

  return 1;
}

/* parses a login packet from the client.
Returns:
1 on success
-1 on failure */
int parse_client_login(packet_t *packet, client_parsed_t *parsed) {
  unsigned char *tmp;

  /* a login request packet is a constant size. If it isn't something is wrong */
  if (packet->header->pckt_sz != LOGIN_REQUEST_SIZE)
    return -1;

  parsed->log_packet.username = safe_malloc(USERNAME_MAX+1 * sizeof *parsed->log_packet.username);
  parsed->log_packet.hash_password = safe_malloc(SHA256_DIGEST_LENGTH+1 * sizeof *parsed->log_packet.hash_password);
  if (parsed->log_packet.username == NULL ||
      parsed->log_packet.hash_password == NULL)
    return -1;

  tmp = packet->payload;

  memcpy(parsed->log_packet.username, tmp, USERNAME_MAX);
  tmp += USERNAME_MAX;
  parsed->log_packet.username[USERNAME_MAX] = '\0';
  memcpy(parsed->log_packet.hash_password, tmp, SHA256_DIGEST_LENGTH);
  parsed->log_packet.hash_password[SHA256_DIGEST_LENGTH] = '\0';

  return 1;
}

/* parses a /users request from the client, ensuring that the payload is correct etc.
It places nothing into the parsed struct as no data for this request is required, other than to
verify the signature
Returns:
1 on success
-1 on failure */
int parse_client_users(packet_t *packet, client_parsed_t *parsed) {
  char msg[USERS_MSG_SIZE+1];

  if (parsed == NULL)
    return -1;

  if (packet->header->pckt_sz != USERS_MSG_SIZE)
    return -1;

  /* compares the expected payload message (constant) with the one provided
  in the packet */
  memcpy(msg, packet->payload, USERS_MSG_SIZE);
  msg[USERS_MSG_SIZE] = '\0';
  if (strncmp(msg, USERS_MSG_PAYLOAD, USERS_MSG_SIZE) != 0)
    return -1;

  return 1;
}

/* parses a public message packet. The certificate that is provided with the message
is ignored as a copy already exists in the database
Returns:
1 on success
-1 on failure  */
int parse_client_pubmsg(packet_t *packet, client_parsed_t *parsed) {
  unsigned int publen, msglen, total;
  unsigned char *tmp, *tmpend;

  tmp = packet->payload;
  total = packet->header->pckt_sz;
  tmpend = tmp + total;

  /* this reads the size of the certificate and skips over it, as it is not needed on the
  server side */
  if ((tmp + sizeof(unsigned int)) > tmpend)
    return -1;
  memcpy(&publen, tmp, sizeof(unsigned int));
  tmp += publen + sizeof(unsigned int);
  /* check if the length of certificate exceeds the pointer limit */
  if (tmp > tmpend)
    return -1;

  /* skip over the username */
  if ((tmp + USERNAME_MAX) > tmpend)
    return -1;
  tmp += USERNAME_MAX;

  /* copy the actual public message */
  memcpy(&msglen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  /* check if current pointer plus the length of the message makes it exceed the limit */
  if ((tmp + msglen) > tmpend)
    return -1;

  parsed->pubmsg_packet.sig = safe_malloc(packet->header->siglen+1 * sizeof *parsed->pubmsg_packet.sig);
  parsed->pubmsg_packet.message = safe_malloc(msglen+1 * sizeof *parsed->pubmsg_packet.message);
  if (parsed->pubmsg_packet.sig == NULL ||
      parsed->pubmsg_packet.message == NULL)
    return -1;

  /* copies the message from payload to parsed struct and the signature too. The signature is
  copied from the header */
  memcpy(parsed->pubmsg_packet.message, tmp, msglen);
  parsed->pubmsg_packet.message[msglen] = '\0';
  memcpy(parsed->pubmsg_packet.sig, packet->header->sig, packet->header->siglen);
  parsed->pubmsg_packet.sig[packet->header->siglen] = '\0';
  parsed->pubmsg_packet.siglen = packet->header->siglen;
  parsed->pubmsg_packet.msg_sz = msglen;

  return 1;
}

/* handles a client request for another users public key
Returns:
1 on succes
-1 on failure */
int parse_client_pubkey_rqst(packet_t *packet, client_parsed_t *parsed) {
  unsigned char *tmp, *tmpend;
  unsigned int size;

  size = packet->header->pckt_sz;
  tmp = packet->payload;
  tmpend = tmp + size;

  /* copy the signature of the packet to the parsed struct. To be used to verify the
  validity of a server response to the request */
  parsed->pubkey_rqst.siglen = packet->header->siglen;
  parsed->pubkey_rqst.sig = safe_malloc(parsed->pubkey_rqst.siglen+1 * sizeof *parsed->pubkey_rqst.sig);
  if (parsed->pubkey_rqst.sig == NULL)
    return -1;
  memcpy(parsed->pubkey_rqst.sig, packet->header->sig, parsed->pubkey_rqst.siglen);
  parsed->pubkey_rqst.sig[parsed->pubkey_rqst.siglen] = '\0';

  /* check the packet contains the minimum required size */
  if ((tmp + USERNAME_MAX + IV_SIZE + sizeof(unsigned int)) > tmpend) {
    fprintf(stderr, "request packet fails minimum size check\n");
    return -1;
  }

  parsed->pubkey_rqst.username = safe_malloc(USERNAME_MAX+1 * sizeof *parsed->pubkey_rqst.username);
  if (parsed->pubkey_rqst.username == NULL)
    return -1;

  memset(parsed->pubkey_rqst.username, '\0', USERNAME_MAX+1);
  memcpy(parsed->pubkey_rqst.username, tmp, USERNAME_MAX);

  /* copy the original packet into the parse struct to make it easier to recreate the packet to return */
  parsed->pubkey_rqst.original = safe_malloc(size+1 * sizeof *parsed->pubkey_rqst.original);
  if (parsed->pubkey_rqst.original == NULL)
    return -1;
  memcpy(parsed->pubkey_rqst.original, packet->payload, size);
  parsed->pubkey_rqst.original[size] = '\0';
  parsed->pubkey_rqst.original_sz = size;

  return 1;
}

/* this function parses a private message packet
Returns:
1 on success
-1 on failure */
int parse_client_privmsg(packet_t *packet, client_parsed_t *parsed) {
  unsigned char *tmp, *tmpend;
  unsigned int size, certlen;

  size = packet->header->pckt_sz;
  tmp = packet->payload;
  tmpend = tmp + size;

  /* copy signature and its size into the parse struct */
  parsed->privmsg_packet.siglen = packet->header->siglen;
  parsed->privmsg_packet.sig = safe_malloc(parsed->privmsg_packet.siglen+1 * sizeof *parsed->privmsg_packet.sig);
  if (parsed->privmsg_packet.sig == NULL)
    return -1;
  memcpy(parsed->privmsg_packet.sig, packet->header->sig, parsed->privmsg_packet.siglen);
  parsed->privmsg_packet.sig[parsed->privmsg_packet.siglen] = '\0';

  /* read the size of the certificate and skip over it. It is not needed on the server side */
  if ((tmp + sizeof(unsigned int)) > tmpend)
    return -1;
  memcpy(&certlen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  if ((tmp + certlen) > tmpend)
    return -1;
  tmp += certlen;

  /* the username does not need to be copied and is skipped over */
  if ((tmp + USERNAME_MAX) > tmpend)
    return -1;
  tmp += USERNAME_MAX;

  /* reads the message into the parse struct */
  if ((tmp + sizeof(unsigned int)) > tmpend)
    return -1;
  memcpy(&parsed->privmsg_packet.msg_sz, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);

  if ((tmp + parsed->privmsg_packet.msg_sz) > tmpend)
    return -1;
  parsed->privmsg_packet.message = safe_malloc(parsed->privmsg_packet.msg_sz+1 * sizeof *parsed->privmsg_packet.message);
  if (parsed->privmsg_packet.message == NULL)
    return -1;
  memcpy(parsed->privmsg_packet.message, tmp, parsed->privmsg_packet.msg_sz);
  parsed->privmsg_packet.message[parsed->privmsg_packet.msg_sz] = '\0';
  tmp += parsed->privmsg_packet.msg_sz;

  /* reads the recipient into the struct */
  if ((tmp + USERNAME_MAX) > tmpend)
    return -1;
  parsed->privmsg_packet.recipient = safe_malloc(USERNAME_MAX+1 * sizeof *parsed->privmsg_packet.recipient);
  if (parsed->privmsg_packet.recipient == NULL)
    return -1;
  memset(parsed->privmsg_packet.recipient, '\0', USERNAME_MAX+1);
  memcpy(parsed->privmsg_packet.recipient, tmp, USERNAME_MAX);
  tmp += USERNAME_MAX;

  /* reads the initialization vector into the struct */
  if ((tmp + IV_SIZE) > tmpend)
    return -1;
  parsed->privmsg_packet.iv = safe_malloc(IV_SIZE+1 * sizeof *parsed->privmsg_packet.iv);
  if (parsed->privmsg_packet.iv == NULL)
    return -1;
  memcpy(parsed->privmsg_packet.iv, tmp, IV_SIZE);
  parsed->privmsg_packet.iv[IV_SIZE] = '\0';
  tmp += IV_SIZE;

  /* read the symmetric key encrypted for the sender */
  if ((tmp + sizeof(unsigned int)) > tmpend)
    return -1;
  memcpy(&parsed->privmsg_packet.s_symkeylen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);

  if ((tmp + parsed->privmsg_packet.s_symkeylen) > tmpend)
    return -1;
  parsed->privmsg_packet.s_symkey = safe_malloc(parsed->privmsg_packet.s_symkeylen+1 * sizeof *parsed->privmsg_packet.s_symkey);
  if (parsed->privmsg_packet.s_symkey == NULL)
    return -1;
  memcpy(parsed->privmsg_packet.s_symkey, tmp, parsed->privmsg_packet.s_symkeylen);
  parsed->privmsg_packet.s_symkey[parsed->privmsg_packet.s_symkeylen] = '\0';
  tmp += parsed->privmsg_packet.s_symkeylen;

  /* read the symmetric key encrypted for the recipient */
  if ((tmp + sizeof(unsigned int)) > tmpend)
    return -1;
  memcpy(&parsed->privmsg_packet.r_symkeylen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);

  if ((tmp + parsed->privmsg_packet.r_symkeylen) > tmpend)
    return -1;
  parsed->privmsg_packet.r_symkey = safe_malloc(parsed->privmsg_packet.r_symkeylen+1 * sizeof *parsed->privmsg_packet.r_symkey);
  if (parsed->privmsg_packet.r_symkey == NULL)
    return -1;
  memcpy(parsed->privmsg_packet.r_symkey, tmp, parsed->privmsg_packet.r_symkeylen);
  parsed->privmsg_packet.r_symkey[parsed->privmsg_packet.r_symkeylen] = '\0';

  return 1;
}

/* sets the pointers of the parsed struct to null for the type of the parsed struct
passed to it */
void initialize_client_parsed(client_parsed_t *p) {
  if (p == NULL)
    return;

  switch (p->id) {
    case C_MSG_EXIT:
      /* nothing to initialize */
      break;
    case C_MSG_LOGIN:
      p->log_packet.username = NULL;
      p->log_packet.hash_password = NULL;
      break;
    case C_MSG_REGISTER:
      p->reg_packet.username = NULL;
      p->reg_packet.hash_password = NULL;
      p->reg_packet.cert = NULL;
      p->reg_packet.iv = NULL;
      p->reg_packet.encrypted_keys = NULL;
      break;
    case C_MSG_PRIVMSG:
      p->privmsg_packet.sig = NULL;
      p->privmsg_packet.message = NULL;
      p->privmsg_packet.recipient = NULL;
      p->privmsg_packet.iv = NULL;
      p->privmsg_packet.s_symkey = NULL;
      p->privmsg_packet.r_symkey = NULL;
      break;
    case C_MSG_PUBMSG:
      p->pubmsg_packet.sig = NULL;
      p->pubmsg_packet.message = NULL;
      break;
    case C_MSG_USERS:
      /* nothing to initialize */
      break;
    case C_META_PUBKEY_RQST:
      p->pubkey_rqst.username = NULL;
      p->pubkey_rqst.sig = NULL;
      p->pubkey_rqst.original = NULL;
      break;
    default:
      break;
  }
}

/* checks whether a given client_parsed_t struct has all of its variables
properly allocated*/
bool is_client_parsed_legal(client_parsed_t *p) {
  if (p == NULL)
    return false;

  switch (p->id) {
    case C_MSG_EXIT:
      /* nothing to check in this instance */
      break;
    case C_MSG_LOGIN:
      if (p->log_packet.username == NULL ||
          p->log_packet.hash_password == NULL)
        return false;
      break;
    case C_MSG_REGISTER:
      if (p->reg_packet.username == NULL ||
          p->reg_packet.hash_password == NULL ||
          p->reg_packet.cert == NULL ||
          p->reg_packet.iv == NULL ||
          p->reg_packet.encrypted_keys == NULL)
        return false;
      break;
    case C_MSG_PRIVMSG:
      if (p->privmsg_packet.sig == NULL ||
          p->privmsg_packet.message == NULL ||
          p->privmsg_packet.recipient == NULL ||
          p->privmsg_packet.iv == NULL ||
          p->privmsg_packet.s_symkey == NULL ||
          p->privmsg_packet.r_symkey == NULL)
        return false;
      break;
    case C_MSG_PUBMSG:
      if (p->pubmsg_packet.sig == NULL ||
          p->pubmsg_packet.message == NULL)
        return false;
      break;
    case C_MSG_USERS:
      /* nothing to check in this instance */
      break;
    case C_META_PUBKEY_RQST:
      if (p->pubkey_rqst.username == NULL ||
          p->pubkey_rqst.sig == NULL ||
          p->pubkey_rqst.original == NULL)
        return false;
      break;
    default:
      break;
  }
  return true;
}

/* frees a given client_parsed_t struct */
void free_client_parsed(client_parsed_t *p) {
  if (p == NULL)
    return;

  switch (p->id) {
    case C_MSG_EXIT:
      /* nothing to free in this instance */
      break;
    case C_MSG_LOGIN:
      free(p->log_packet.username);
      free(p->log_packet.hash_password);
      break;
    case C_MSG_REGISTER:
      free(p->reg_packet.username);
      free(p->reg_packet.hash_password);
      free(p->reg_packet.cert);
      free(p->reg_packet.iv);
      free(p->reg_packet.encrypted_keys);
      break;
    case C_MSG_PRIVMSG:
      free(p->privmsg_packet.sig);
      free(p->privmsg_packet.message);
      free(p->privmsg_packet.recipient);
      free(p->privmsg_packet.iv);
      free(p->privmsg_packet.s_symkey);
      free(p->privmsg_packet.r_symkey);
      break;
    case C_MSG_PUBMSG:
      free(p->pubmsg_packet.sig);
      free(p->pubmsg_packet.message);
      break;
    case C_MSG_USERS:
      /* nothing to free in this instance */
      break;
    case C_META_PUBKEY_RQST:
      free(p->pubkey_rqst.username);
      free(p->pubkey_rqst.sig);
      free(p->pubkey_rqst.original);
      break;
    default:
      break;
  }

  free(p);
}

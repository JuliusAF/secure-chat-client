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

  parsed = safe_malloc(sizeof(client_parsed_t));

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
      break;
    case C_MSG_PUBMSG:
      ret = parse_client_pubmsg(p, parsed);
      break;
    case C_MSG_USERS:
      ret = parse_client_users(p, parsed);
      break;
    case C_META_PUBKEY_RQST:
      break;
    default:
      ret = -1;
      break;
  }

  if (ret < 0) {
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

  if (!is_packet_legal(packet) || parsed == NULL ||
      parsed->id != C_MSG_REGISTER)
    return -1;

  /* checks that the packet payload size is at least as large as the known size
  reuirements. (there are some fixed sizes to the packet, and some of variable size )*/
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
  parsed->reg_packet.username = safe_malloc(sizeof(char) * USERNAME_MAX+1);
  if (parsed->reg_packet.username == NULL)
    return -1;
  parsed->reg_packet.hash_password = safe_malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH+1);
  if (parsed->reg_packet.hash_password == NULL)
    return -1;
  parsed->reg_packet.iv = safe_malloc(sizeof(char) * IV_SIZE+1);
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
  memcpy(&parsed->reg_packet.publen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  /* check that the payload has enough space for at least up to the next instance of
  a variable size input */
  if (tmp + parsed->reg_packet.publen + IV_SIZE + sizeof(unsigned int) > tmpend) {
    fprintf(stderr, "failed to copy register data 1, would overflow pointer\n");
    return -1;
  }

  parsed->reg_packet.pubkey = safe_malloc(sizeof(unsigned char) * parsed->reg_packet.publen+1);
  if (parsed->reg_packet.pubkey == NULL)
    return -1;

  memcpy(parsed->reg_packet.pubkey, tmp, parsed->reg_packet.publen);
  tmp += parsed->reg_packet.publen;
  parsed->reg_packet.pubkey[parsed->reg_packet.publen] = '\0';
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

  parsed->reg_packet.encrypted_keys =
    safe_malloc(sizeof(unsigned char) * parsed->reg_packet.encrypt_sz+1);
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

  if (!is_packet_legal(packet) || parsed == NULL ||
      parsed->id != C_MSG_LOGIN)
    return -1;

  /* a login request packet is a constant size. If it isn't something is wrong */
  if (packet->header->pckt_sz != LOGIN_REQUEST_SIZE)
    return -1;

  parsed->log_packet.username = safe_malloc(sizeof(char) * USERNAME_MAX+1);
  parsed->log_packet.hash_password = safe_malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH+1);
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
Returns:
1 on success
-1 on failure */
int parse_client_users(packet_t *packet, client_parsed_t *parsed) {
  char msg[USERS_MSG_SIZE+1];

  if (!is_packet_legal(packet) || parsed == NULL)
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

/* parses a public message packet. The public key that is provided with the message
is ignored as a copy already exists in the database
Returns:
1 on success
-1 on failure  */
int parse_client_pubmsg(packet_t *packet, client_parsed_t *parsed) {
  unsigned int publen, msglen, total;
  unsigned char *tmp, *tmpend;

  if (!is_packet_legal(packet) || parsed == NULL)
    return -1;

  tmp = packet->payload;
  total = packet->header->pckt_sz;
  tmpend = tmp + total;

  memcpy(&publen, tmp, sizeof(unsigned int));
  tmp += (sizeof(unsigned int) + publen);
  /* check if the length of public key and size of length exceeds the pointer limit */
  if (tmp > tmpend)
    return -1;

  memcpy(&msglen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  /* check if current pointer plus the length of the message makes it exceed the limit */
  if ((tmp + msglen) > tmpend)
    return -1;

  parsed->pubmsg_packet.sig = safe_malloc(sizeof(unsigned char) * packet->header->siglen+1);
  parsed->pubmsg_packet.message = safe_malloc(sizeof(char) * msglen+1);
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
      p->reg_packet.pubkey = NULL;
      p->reg_packet.iv = NULL;
      p->reg_packet.encrypted_keys = NULL;
      break;
    case C_MSG_PRIVMSG:
      break;
    case C_MSG_PUBMSG:
      p->pubmsg_packet.sig = NULL;
      p->pubmsg_packet.message = NULL;
      break;
    case C_MSG_USERS:
      /* nothing to initialize */
      break;
    case C_META_PUBKEY_RQST:
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
          p->reg_packet.pubkey == NULL ||
          p->reg_packet.iv == NULL ||
          p->reg_packet.encrypted_keys == NULL)
        return false;
      break;
    case C_MSG_PRIVMSG:
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
      free(p->reg_packet.pubkey);
      free(p->reg_packet.iv);
      free(p->reg_packet.encrypted_keys);
      break;
    case C_MSG_PRIVMSG:
      break;
    case C_MSG_PUBMSG:
      free(p->pubmsg_packet.sig);
      free(p->pubmsg_packet.message);
      break;
    case C_MSG_USERS:
      /* nothing to free in this instance */
      break;
    case C_META_PUBKEY_RQST:
      break;
    default:
      break;
  }

  free(p);
}

#include "parse_server_input.h"

/* these functions detail the parsing of a packet that was sent from server
to the client */

/* parses a packet from server into the server_parsed_t struct and returns it */
server_parsed_t *parse_server_input(packet_t *p) {
  int ret;
  unsigned int packet_size;
  server_parsed_t *parsed;

  if (!is_packet_legal(p)) {
    fprintf(stderr, "packet not legal in parse_server_input\n");
    return NULL;
  }

  packet_size = p->header->pckt_sz + HEADER_SIZE;
  if (packet_size > MAX_PACKET_SIZE) {
    fprintf(stderr, "packet size larger than max in parse_server_input\n");
    return NULL;
  }
  if (p->header->siglen > MAX_SIG_SZ) {
    fprintf(stderr, "signature length larger than max in parse_server_input\n");
  }

  parsed = safe_malloc(sizeof *parsed);
  if (parsed == NULL)
    return NULL;

  parsed->id = p->header->pckt_id;
  /* sets relevant pointers to NULL */
  initialize_server_parsed(parsed);

  switch (parsed->id) {
    case S_MSG_PUBMSG:
      ret = parse_server_msg(p, parsed);
      break;
    case S_MSG_PRIVMSG:
      ret = parse_server_msg(p, parsed);
      break;
    case S_MSG_USERS:
      ret = parse_server_users(p, parsed);
      break;
    case S_MSG_GENERIC_ERR:
      ret = parse_server_error(p, parsed);
      break;
    case S_META_LOGIN_PASS:
      ret = parse_server_userinfo(p, parsed);
      break;
    case S_META_LOGIN_FAIL:
      ret = parse_server_error(p, parsed);
      break;
    case S_META_REGISTER_PASS:
      ret = parse_server_userinfo(p, parsed);
      break;
    case S_META_REGISTER_FAIL:
      ret = parse_server_error(p, parsed);
      break;
    case S_META_PUBKEY_RESPONSE:
      ret = parse_server_pubkey_response(p, parsed);
      break;
    default:
      ret = -1;
      break;
  }
  /* if an error during parsing occurs, the parse struct is freed */
  if (ret < 0) {
    printf("server parsed ret: %d\n", ret);
    free_server_parsed(parsed);
    return NULL;
  }
  return parsed;
}

/* parses a packet that contains a list of users in byte array format from
the server
Returns:
1 on success
-1 on failure */
int parse_server_users(packet_t *packet, server_parsed_t *parsed) {
  unsigned size;
  char *users;
  if (!is_packet_legal(packet) || parsed == NULL)
    return -1;

  size = packet->header->pckt_sz;
  users = safe_malloc(size+1 * sizeof *users);
  if (users == NULL)
    return -1;
  memcpy(users, packet->payload, size);
  users[size] = '\0';
  parsed->users = users;

  return 1;
}

/* parses a packet that contains user data into the respective struct. Both
login success and register success can return a packet that contains user info
which is parsed into the same struct data fields here.
Returns:
1 on success
-1 on failure */
int parse_server_userinfo(packet_t *packet, server_parsed_t *parsed) {
  unsigned int size;
  unsigned char *tmp, *tmpend;

  if (!is_packet_legal(packet) || parsed == NULL ||
      (parsed->id != S_META_LOGIN_PASS &&
      parsed->id != S_META_REGISTER_PASS))
    return -1;

  size = packet->header->pckt_sz;
  tmp = packet->payload;
  tmpend = tmp + size;

  /* checks if the payload has the minimum required size of bytes*/
  if ((tmp + IV_SIZE + sizeof(unsigned int)) > tmpend) {
    fprintf(stderr, "user info packet fails to meet minimum size\n");
    return -1;
  }

  parsed->user_details.iv = safe_malloc(IV_SIZE+1 * sizeof *parsed->user_details.iv);
  if (parsed->user_details.iv == NULL)
    return -1;

  memcpy(parsed->user_details.iv, tmp, IV_SIZE);
  parsed->user_details.iv[IV_SIZE] = '\0';
  tmp += IV_SIZE;
  memcpy(&parsed->user_details.encrypt_sz, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);

  /* check if the payload buffer overflows if the size of the keys is read from it */
  if ((tmp + parsed->user_details.encrypt_sz) > tmpend) {
    fprintf(stderr, "failed to copy encrypted keys in user info. would overflow\n");
    return -1;
  }

  parsed->user_details.encrypted_keys = safe_malloc(parsed->user_details.encrypt_sz+1 * sizeof *parsed->user_details.encrypted_keys);
  if (parsed->user_details.encrypted_keys == NULL)
    return -1;

  memcpy(parsed->user_details.encrypted_keys, tmp, parsed->user_details.encrypt_sz);
  parsed->user_details.encrypted_keys[parsed->user_details.encrypt_sz] = '\0';

  return 1;
}

/* parses a message packet from the server. It handles both private and public
messages as they differ statically and can be processed similarly
Returns:
1 on success
-1 on failure */
int parse_server_msg(packet_t *packet, server_parsed_t *parsed) {
  unsigned int size, hashlen;
  unsigned char *tmp, *tmpend;

  if (!is_packet_legal(packet))
    return -1;

  size = packet->header->pckt_sz;
  tmp = packet->payload;
  tmpend = tmp+size;


  /* the returned sizes must be checked to discover memory overflows.
  Inputs the signature and its length into the struct */
  if ((tmp + sizeof(unsigned int)) > tmpend)
    return -1;
  memcpy(&parsed->messages.siglen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  if((tmp + parsed->messages.siglen) > tmpend)
    return -1;

  parsed->messages.sig = safe_malloc(parsed->messages.siglen+1 * sizeof *parsed->messages.sig);
  if (parsed->messages.sig == NULL)
    return -1;
  memcpy(parsed->messages.sig, tmp, parsed->messages.siglen);
  parsed->messages.sig[parsed->messages.siglen] = '\0';
  tmp += parsed->messages.siglen;

  /* the original payload that was sent to the server when a public/private message
  was made was signed by that client. That payload must be found now and hashed, in order
  to verify the signature. The pointer tmp at its current position points to that original payload */
  hashlen = tmpend - tmp;
  parsed->messages.hashed_payload = hash_input( (char *) tmp, hashlen);
  if (parsed->messages.hashed_payload == NULL)
    return -1;

  /* parse the certificate length and certificate into the struct and checks for memory errors */
  if ((tmp + sizeof(unsigned int)) > tmpend)
    return -1;
  memcpy(&parsed->messages.certlen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  if ((tmp + parsed->messages.certlen) > tmpend)
    return -1;

  parsed->messages.cert = safe_malloc(parsed->messages.certlen+1 * sizeof *parsed->messages.cert);
  if (parsed->messages.cert == NULL)
    return -1;
  memcpy(parsed->messages.cert, tmp, parsed->messages.certlen);
  parsed->messages.cert[parsed->messages.certlen] = '\0';
  tmp += parsed->messages.certlen;

  if ((tmp + USERNAME_MAX) > tmpend)
    return -1;
  parsed->messages.sender = safe_malloc(USERNAME_MAX+1 * sizeof *parsed->messages.sender);
  memset(parsed->messages.sender, '\0', USERNAME_MAX+1);
  memcpy(parsed->messages.sender, tmp, USERNAME_MAX);
  tmp += USERNAME_MAX;

  /* parse the message into the struct and check for memory errors */
  if ((tmp + sizeof(unsigned int)) > tmpend)
    return -1;
  memcpy(&parsed->messages.msglen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  if ((tmp + parsed->messages.msglen) > tmpend)
    return -1;

  parsed->messages.message = safe_malloc(parsed->messages.msglen+1 * sizeof *parsed->messages.message);
  if (parsed->messages.message == NULL)
    return -1;
  memcpy(parsed->messages.message, tmp, parsed->messages.msglen);
  parsed->messages.message[parsed->messages.msglen] = '\0';
  tmp += parsed->messages.msglen;
  
  /* Now only private messages have more input. This is checked here */
  if (parsed->id == S_MSG_PRIVMSG) {
    /* input the recipient into the appropriate variable. This field has a constant
    size defined as USERNAME_MAX */

    if ((tmp + USERNAME_MAX) > tmpend)
      return -1;
    parsed->messages.recipient = safe_malloc(USERNAME_MAX+1 * sizeof *parsed->messages.recipient);
    if (parsed->messages.recipient == NULL)
      return -1;
    memset(parsed->messages.recipient, '\0', USERNAME_MAX+1);
    memcpy(parsed->messages.recipient, tmp, USERNAME_MAX);
    tmp += USERNAME_MAX;

    /* store the initialization vector used to encrypt the private message */
    if ((tmp + IV_SIZE) > tmpend)
      return -1;
    parsed->messages.iv = safe_malloc(IV_SIZE+1 * sizeof *parsed->messages.iv);
    if (parsed->messages.iv == NULL)
      return -1;
    memcpy(parsed->messages.iv, tmp, IV_SIZE);
    parsed->messages.iv[IV_SIZE] = '\0';
    tmp += IV_SIZE;

    /* stores the symmetric key encrypted for the sender */
    if ((tmp + sizeof(unsigned int)) > tmpend)
      return -1;
    memcpy(&parsed->messages.s_symkeylen, tmp, sizeof(unsigned int));
    tmp += sizeof(unsigned int);
    if ((tmp + parsed->messages.s_symkeylen) > tmpend)
      return -1;

    parsed->messages.s_symkey = safe_malloc(parsed->messages.s_symkeylen+1 * sizeof *parsed->messages.s_symkey);
    if (parsed->messages.s_symkey == NULL)
      return -1;
    memcpy(parsed->messages.s_symkey, tmp, parsed->messages.s_symkeylen);
    parsed->messages.s_symkey[parsed->messages.s_symkeylen] = '\0';
    tmp += parsed->messages.s_symkeylen;

    /* stores the symmetric key that was encrypted for the recipient */
    if ((tmp + sizeof(unsigned int)) > tmpend)
      return -1;
    memcpy(&parsed->messages.r_symkeylen, tmp, sizeof(unsigned int));
    tmp += sizeof(unsigned int);
    if ((tmp + parsed->messages.r_symkeylen) > tmpend)
      return -1;

    parsed->messages.r_symkey = safe_malloc(parsed->messages.r_symkeylen+1 * sizeof *parsed->messages.r_symkey);
    if (parsed->messages.r_symkey == NULL)
      return -1;
    memcpy(parsed->messages.r_symkey, tmp, parsed->messages.r_symkeylen);
    parsed->messages.r_symkey[parsed->messages.r_symkeylen] = '\0';
  }
  return 1;
}

/* parses a server response to a public key request.
Returns:
1 on succes
-1 on failure  */
int parse_server_pubkey_response(packet_t *packet, server_parsed_t *parsed) {
  unsigned int size, len_to_hash;
  unsigned char *tmp, *tmpend, *hash;

  if (packet == NULL || parsed == NULL)
    return -1;

  size = packet->header->pckt_sz;
  tmp = packet->payload;
  tmpend = tmp + size;

  /* check if reading the size of the key causes buffer overflow, if not copy it */
  if ((tmp + sizeof(unsigned int)) > tmpend)
    return -1;
  memcpy(&parsed->pubkey_response.certlen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);

  /* check if reading the key causes buffer overflow, if not copy it */
  if ((tmp + parsed->pubkey_response.certlen) > tmpend)
    return -1;
  parsed->pubkey_response.cert = safe_malloc(parsed->pubkey_response.certlen+1 * sizeof *parsed->pubkey_response.cert);
  if (parsed->pubkey_response.cert == NULL)
    return -1;
  memcpy(parsed->pubkey_response.cert, tmp, parsed->pubkey_response.certlen);
  parsed->pubkey_response.cert[parsed->pubkey_response.certlen] = '\0';
  tmp += parsed->pubkey_response.certlen;

  /* copy the size of the signature and the signature into their respective variables */
  if ((tmp + sizeof(unsigned int)) > tmpend)
    return -1;
  memcpy(&parsed->pubkey_response.siglen, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);

  if ((tmp + parsed->pubkey_response.siglen) > tmpend)
    return -1;
  parsed->pubkey_response.sig = safe_malloc(parsed->pubkey_response.siglen+1 * sizeof *parsed->pubkey_response.sig);
  memcpy(parsed->pubkey_response.sig, tmp, parsed->pubkey_response.siglen);
  parsed->pubkey_response.sig[parsed->pubkey_response.siglen] = '\0';
  tmp += parsed->pubkey_response.siglen;

  /* what remains the the packet not is the original payload sent to the server, if it
  was preserved. This is hashed and stored in order to validate the validity of the returned
  message */
  /* remaining size of packet */
  len_to_hash = tmpend - tmp;
  hash = hash_input( (char *) tmp, len_to_hash);
  if (hash == NULL)
    return -1;
  parsed->pubkey_response.hashed_payload = hash;

  /* check if reading the username causes buffer overflow, if not copy it */
  if ((tmp + USERNAME_MAX) > tmpend)
    return -1;
  parsed->pubkey_response.username = safe_malloc(USERNAME_MAX+1 * sizeof *parsed->pubkey_response.username);
  if (parsed->pubkey_response.username == NULL)
    return -1;
  memset(parsed->pubkey_response.username, '\0', USERNAME_MAX+1);
  memcpy(parsed->pubkey_response.username, tmp, USERNAME_MAX);
  tmp += USERNAME_MAX;

  /* checks if the next known required reads cause buffer overflow */
  if ((tmp + IV_SIZE + sizeof(unsigned int)) > tmpend)
    return -1;
  parsed->pubkey_response.iv = safe_malloc(IV_SIZE+1 * sizeof *parsed->pubkey_response.iv);
  if (parsed->pubkey_response.iv == NULL)
    return -1;
  memcpy(parsed->pubkey_response.iv, tmp, IV_SIZE);
  parsed->pubkey_response.iv[IV_SIZE] = '\0';
  tmp += IV_SIZE;

  memcpy(&parsed->pubkey_response.encrypt_sz, tmp, sizeof(unsigned int));
  tmp += sizeof(unsigned int);

  /* check if reading the encrypted message causes buffer overflow, if not copy it */
  if ((tmp + parsed->pubkey_response.encrypt_sz) > tmpend)
    return -1;
  parsed->pubkey_response.encrypted_msg = safe_malloc(parsed->pubkey_response.encrypt_sz+1 * sizeof *parsed->pubkey_response.encrypted_msg);
  if (parsed->pubkey_response.encrypted_msg == NULL)
    return -1;
  memcpy(parsed->pubkey_response.encrypted_msg, tmp, parsed->pubkey_response.encrypt_sz);
  parsed->pubkey_response.encrypted_msg[parsed->pubkey_response.encrypt_sz] = '\0';

  return 1;
}

/* helper function that checks if an id is one of the error ids */
static bool is_id_error(server_parsed_t *p) {
  if (p == NULL)
    return false;

  return (p->id == S_MSG_GENERIC_ERR ||
          p->id == S_META_LOGIN_FAIL ||
          p->id == S_META_REGISTER_FAIL);
}

/* parses a packet with an error code
Returns:
1 on success
-1 on failure  */
int parse_server_error(packet_t *packet, server_parsed_t *parsed) {
  unsigned int size;

  if (!is_packet_legal(packet) || parsed == NULL ||
      !is_id_error(parsed))
    return -1;

  size = packet->header->pckt_sz;
  if (size > MAX_PAYLOAD_SIZE)
    return -1;

  parsed->error_message = safe_malloc(size+1 * sizeof *parsed->error_message);
  if (parsed->error_message == NULL)
    return -1;

  memcpy(parsed->error_message, packet->payload, size);
  parsed->error_message[size] = '\0';

  return 1;
}

/* initializes an pointers in the server_parsed_t struct. Which pointers must
be initialized is dependent on the id of the packet */
void initialize_server_parsed(server_parsed_t *p) {
  if (p == NULL)
    return;

  switch (p->id) {
    /* same cases for these two ids */
    case S_MSG_PUBMSG:
    case S_MSG_PRIVMSG:
      p->messages.sig = NULL;
      p->messages.hashed_payload = NULL;
      p->messages.cert = NULL;
      p->messages.sender = NULL;
      p->messages.message = NULL;
      p->messages.recipient = NULL;
      p->messages.iv = NULL;
      p->messages.s_symkey = NULL;
      p->messages.r_symkey = NULL;
      break;
    case S_MSG_USERS:
      p->users = NULL;
      break;
    case S_MSG_GENERIC_ERR:
      p->error_message = NULL;
      break;
    case S_META_LOGIN_PASS:
      p->user_details.iv = NULL;
      p->user_details.encrypted_keys = NULL;
      break;
    case S_META_LOGIN_FAIL:
      p->error_message = NULL;
      break;
    case S_META_REGISTER_PASS:
      p->user_details.iv = NULL;
      p->user_details.encrypted_keys = NULL;
      break;
    case S_META_REGISTER_FAIL:
      p->error_message = NULL;
      break;
    case S_META_PUBKEY_RESPONSE:
      p->pubkey_response.cert = NULL;
      p->pubkey_response.sig = NULL;
      p->pubkey_response.hashed_payload = NULL;
      p->pubkey_response.username = NULL;
      p->pubkey_response.iv = NULL;
      p->pubkey_response.encrypted_msg = NULL;
      break;
    default:
      break;
  }
}

/* checks if a given server_parsed_t struct has all pointers not NULL*/
bool is_server_parsed_legal(server_parsed_t *p) {
  if (p == NULL)
    return false;

  switch (p->id) {
    case S_MSG_PUBMSG:
      if (p->messages.sig == NULL ||
          p->messages.hashed_payload == NULL ||
          p->messages.cert == NULL ||
          p->messages.sender == NULL ||
          p->messages.message == NULL)
        return false;
      break;
    case S_MSG_PRIVMSG:
      if (p->messages.sig == NULL ||
          p->messages.hashed_payload == NULL ||
          p->messages.cert == NULL ||
          p->messages.sender == NULL ||
          p->messages.message == NULL ||
          p->messages.recipient == NULL ||
          p->messages.iv == NULL ||
          p->messages.s_symkey == NULL ||
          p->messages.r_symkey == NULL)
        return false;
      break;
    case S_MSG_USERS:
      if (p->users == NULL)
        return false;
      break;
    case S_MSG_GENERIC_ERR:
      if (p->error_message == NULL)
        return false;
      break;
    case S_META_LOGIN_PASS:
      if (p->user_details.iv == NULL ||
          p->user_details.encrypted_keys == NULL)
        return false;
      break;
    case S_META_LOGIN_FAIL:
      if (p->error_message == NULL)
        return false;
      break;
    case S_META_REGISTER_PASS:
      if (p->user_details.iv == NULL ||
          p->user_details.encrypted_keys == NULL)
        return false;
      break;
    case S_META_REGISTER_FAIL:
      if (p->error_message == NULL)
        return false;
      break;
    case S_META_PUBKEY_RESPONSE:
      if (p->pubkey_response.cert == NULL ||
          p->pubkey_response.sig == NULL ||
          p->pubkey_response.hashed_payload == NULL ||
          p->pubkey_response.username == NULL ||
          p->pubkey_response.iv == NULL ||
          p->pubkey_response.encrypted_msg == NULL)
        return false;
      break;
    default:
      return false;
  }
  return true;
}

/* frees a given server_parsed_t struct */
void free_server_parsed(server_parsed_t *p) {
  if (p == NULL)
    return;

  switch (p->id) {
    /* same cases for these two ids */
    case S_MSG_PUBMSG:
    case S_MSG_PRIVMSG:
      free(p->messages.sig);
      free(p->messages.hashed_payload);
      free(p->messages.cert);
      free(p->messages.sender);
      free(p->messages.message);
      free(p->messages.recipient);
      free(p->messages.iv);
      free(p->messages.s_symkey);
      free(p->messages.r_symkey);
      break;
    case S_MSG_USERS:
      free(p->users);
      break;
    case S_MSG_GENERIC_ERR:
      free(p->error_message);
      break;
    case S_META_LOGIN_PASS:
      free(p->user_details.iv);
      free(p->user_details.encrypted_keys);
      break;
    case S_META_LOGIN_FAIL:
      free(p->error_message);
      break;
    case S_META_REGISTER_PASS:
      free(p->user_details.iv);
      free(p->user_details.encrypted_keys);
      break;
    case S_META_REGISTER_FAIL:
      free(p->error_message);
      break;
    case S_META_PUBKEY_RESPONSE:
      free(p->pubkey_response.cert);
      free(p->pubkey_response.sig);
      free(p->pubkey_response.hashed_payload);
      free(p->pubkey_response.username);
      free(p->pubkey_response.iv);
      free(p->pubkey_response.encrypted_msg);
      break;
    default:
      break;
  }
  free(p);
}

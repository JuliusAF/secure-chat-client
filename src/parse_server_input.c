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

  parsed = safe_malloc(sizeof(server_parsed_t));
  if (parsed == NULL)
    return NULL;

  parsed->id = p->header->pckt_id;
  /* sets relevant pointers to NULL */
  initialize_server_parsed(parsed);

  switch (parsed->id) {
    case S_MSG_PUBMSG:
      break;
    case S_MSG_PRIVMSG:
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
    default:
      ret = -1;
      break;
  }
  /* if an error during parsing occurs, the parse struct is freed */
  if (ret < 0) {
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
  users = safe_malloc(sizeof(char) * size+1);
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

  parsed->user_details.iv = safe_malloc(sizeof(unsigned char) * IV_SIZE+1);
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

  parsed->user_details.encrypted_keys = safe_malloc(sizeof(unsigned char) * parsed->user_details.encrypt_sz+1);
  if (parsed->user_details.encrypted_keys == NULL)
    return -1;

  memcpy(parsed->user_details.encrypted_keys, tmp, parsed->user_details.encrypt_sz);
  parsed->user_details.encrypted_keys[parsed->user_details.encrypt_sz] = '\0';

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

  parsed->error_message = safe_malloc(sizeof(char) * size+1);
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
    case S_MSG_PUBMSG:
      break;
    case S_MSG_PRIVMSG:
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
      break;
    case S_MSG_PRIVMSG:
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
    case S_MSG_PUBMSG:
      break;
    case S_MSG_PRIVMSG:
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
    default:
      break;
  }
  free(p);
}

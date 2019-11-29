#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "parser.h"
#include "network.h"
#include "safe_wrappers.h"

static const char delim[] = " \n\t\v";

void print_hex(unsigned char *hex, int len) {
  printf("hexadecimals: ");
  for (int i = 0; i < len; i++) {
    printf("%x", hex[i]);
  }
  printf("END\n");
}

bool is_digit(const char *s) {
  for (size_t i = 0; i < strlen(s); i++)
    if(!isdigit(s[i]))
      return false;
  return true;
}

char* trim_front_whitespace(char* input) {
  if (!input)
    return input;

  char *input_end = input + strlen(input);

  while (isspace(input[0]) && input < input_end)
    input++;

  return input;
}

int trim_back_whitespace(char* input) {
  int input_size;

  if (input == NULL)
    return -1;

  input_size = strlen(input);

  while (isspace(input[input_size-1]) && input_size != 0)
    input_size--;
  input[input_size] = '\0';
  return input_size;
}

static bool is_message_legal(char *input) {
  if (input[0] == '/' || input[0] == '@' || input == NULL || input[0] == '\0')
    return false;

  for (size_t i = 0; i < strlen(input); i++)
    if (input[i] == '\n')
      return false;
  return true;
}

/* checks if a string conforms to the syntax restrictions of tokens
as described in the manual*/
static bool is_token_legal(char *input) {
  if (input == NULL)
    return false;

  for (size_t i = 0; i < strlen(input); i++)
    if (input[0] == ' ' || input[0] == '\n')
      return false;
  return true;
}

void make_error(command_t *node, char *s) {
  node->command = COMMAND_ERROR;
  node->error_message = safe_strdup(s);
}

/* The following functions are helper functions to
parse_input() that error check user input and if there are no errors,
it places the fields belonging to some input into a node of type command_t*/

command_t *make_exit_node(char *input) {
  command_t *node = safe_malloc(sizeof(command_t));

  if (strcmp(input,"/exit") != 0)
    make_error(node, "User input after '/exit'. Incorrect command");
  else
    node->command = COMMAND_EXIT;
  return node;
}

command_t* make_login_node(char *input) {
  command_t *node = safe_malloc(sizeof(command_t));
  char *temp = malloc(sizeof(char) * (strlen(input)+1)),
  *token, *username, *password;

  memcpy(temp, input, strlen(input)+1);
  token = strtok(temp, delim);
  token = strtok(NULL, delim);

  if (!is_token_legal(token))
    make_error(node, "Username follows incorrect syntax");
  else if (strlen(token) > USERNAME_MAX)
    make_error(node, "Username larger than 20 characters");
  else {
    username = safe_strdup(token);
    token = strtok(NULL, delim);
    if (token == NULL) {
      make_error(node, "No password provided");
      free(username);
      free(temp);
      return node;
    }
    password = safe_strdup(token);
    token = strtok(NULL, delim);

    if (token != NULL)
      make_error(node, "More user input after account details");
    else if (!is_token_legal(password))
      make_error(node, "Password follows incorrect syntax");
    else if (strlen(password) > PASSWORD_MAX)
      make_error(node, "Password larger than 24 characters");
    else {
      node->command = COMMAND_LOGIN;
      node->acc_details.username = safe_strdup(username);
      node->acc_details.password = safe_strdup(password);
    }
    free(username);
    free(password);
  }

  free(temp);
  return node;
}

command_t* make_register_node(char *input) {
  command_t *node;
  node = make_login_node(input);
  /* register uses the same syntax and fields as login. Therefore only the type
  has to be changed*/
  if (node->command == COMMAND_LOGIN)
    node->command = COMMAND_REGISTER;

  return node;
}

command_t *make_privmsg_node(char *input) {
  int token_size;
  command_t *node = safe_malloc(sizeof(command_t));
  char *temp = safe_malloc(sizeof(char)*(strlen(input)+1)), *tmp_msg,
  *token, *username;

  memcpy(temp, input, strlen(input)+1);
  token = strtok(temp, delim);
  token_size = strlen(token);
  if (token == NULL || token_size < 2) {
    make_error(node, "No recipient for private message");
    free(temp);
    return node;
  }

  username = safe_strdup(token+1);
  if (!is_token_legal(username))
    make_error(node, "Impossible recipient name");
  else {
    /* increments the pointer of a copy of the input to the beginning of the message field.
    The pointer is copied so that the original can be freed later */
    memcpy(temp, input, strlen(input)+1);
    tmp_msg = temp;
    tmp_msg += token_size;
    tmp_msg = trim_front_whitespace(tmp_msg);
    trim_back_whitespace(tmp_msg);

    if (!is_message_legal(tmp_msg))
      make_error(node, "Message follows incorrect syntax or is empty");
    else if (strlen(tmp_msg) > MESSAGE_MAX)
      make_error(node, "Message is greater than 200 characters");
    else {
      node->command = COMMAND_PRIVMSG;
      node->privmsg.username = safe_strdup(username);
      node->privmsg.message = safe_strdup(tmp_msg);
    }
  }

  free(username);
  free(temp);
  return node;
}

command_t* make_pubmsg_node(char *input) {
  command_t *node = safe_malloc(sizeof(command_t));

  if (!is_message_legal(input))
    make_error(node, "Message follows incorrect syntax or is empty");
  else if (strlen(input) > MESSAGE_MAX)
    make_error(node, "Message is greater than 200 characters");
  else {
    node->command = COMMAND_PUBMSG;
    node->message = safe_strdup(input);
  }

  return node;
}

command_t* make_users_node(char *input) {
  command_t *node = safe_malloc(sizeof(command_t));

  if (strcmp(input,"/users") != 0)
    make_error(node, "User input after 'users'. Incorrect command");
  else {
    node->command = COMMAND_USERS;
  }

  return node;
}

command_t *parse_input(char *input) {
  char *formatted_input, *temp, *token;
  int input_size;
  command_t *node;

  formatted_input = trim_front_whitespace(input);
  input_size = trim_back_whitespace(formatted_input);
  if (formatted_input == NULL || input_size < 1)
    return NULL;
  temp = (char *) malloc(sizeof(char) * (strlen(formatted_input)+1));
  memcpy(temp, formatted_input, strlen(formatted_input)+1);
  token = strtok(temp, delim);

  if (strcmp(token,"/exit") == 0)
    node = make_exit_node(formatted_input);
  else if (strcmp(token,"/login") == 0)
    node = make_login_node(formatted_input);
  else if (strcmp(token,"/register") == 0)
    node = make_register_node(formatted_input);
  else if (strcmp(token,"/users") == 0)
    node = make_users_node(formatted_input);
  else if (token[0] == '@')
    node = make_privmsg_node(formatted_input);
  else
    node = make_pubmsg_node(formatted_input);

  if(!is_node_legal(node)) {
    free_node(node);
    node = NULL;
  }

  free(temp);
  return node;
}

/* checks if all the data fields ar enot null. If they are strdup probably failed*/
bool is_node_legal(command_t *node) {
  if (node == NULL)
    return false;

  switch (node->command) {
    case COMMAND_EXIT:
      break;
    case COMMAND_LOGIN:
      if (node->acc_details.username == NULL)
        return false;
      if (node->acc_details.password == NULL)
        return false;
      break;
    case COMMAND_REGISTER:
      if (node->acc_details.username == NULL)
        return false;
      if (node->acc_details.password == NULL)
        return false;
      break;
    case COMMAND_PRIVMSG:
      if (node->privmsg.username == NULL)
        return false;
      if (node->privmsg.message == NULL)
        return false;
      break;
    case COMMAND_PUBMSG:
      if (node->message == NULL)
        return false;
      break;
    case COMMAND_USERS:
      break;
    case COMMAND_ERROR:
      if (node->error_message == NULL)
        return false;
      break;
    default:
      break;
  }

  return true;
}

/* Frees the individual parts of a node and then the node itself*/
void free_node(command_t *node) {
  if (node == NULL)
    return;

  switch (node->command) {
    case COMMAND_ERROR:
      free(node->error_message);
      break;
    case COMMAND_LOGIN:
      free(node->acc_details.username);
      free(node->acc_details.password);
      break;
    case COMMAND_REGISTER:
      free(node->acc_details.username);
      free(node->acc_details.password);
      break;
    case COMMAND_PUBMSG:
      free(node->message);
      break;
    case COMMAND_PRIVMSG:
      free(node->privmsg.username);
      free(node->privmsg.message);
      break;
    default:
      break;
  }

  free(node);
}

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

  parsed = (client_parsed_t *) safe_malloc(sizeof(client_parsed_t));

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
      break;
    case C_MSG_USERS:
      ret = -1;
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
  parsed->reg_packet.username = (char *) safe_malloc(sizeof(char) * USERNAME_MAX+1);
  if (parsed->reg_packet.username == NULL)
    return -1;
  parsed->reg_packet.hash_password =
      (unsigned char *) safe_malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH+1);
  if (parsed->reg_packet.hash_password == NULL)
    return -1;
  parsed->reg_packet.iv = (unsigned char *) safe_malloc(sizeof(char) * IV_SIZE+1);
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

  parsed->reg_packet.pubkey = (char *) safe_malloc(sizeof(unsigned char) * parsed->reg_packet.publen+1);
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
    (unsigned char *) safe_malloc(sizeof(unsigned char) * parsed->reg_packet.encrypt_sz+1);
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

  parsed->log_packet.username = (char *) safe_malloc(sizeof(char) * USERNAME_MAX+1);
  parsed->log_packet.hash_password =
      (unsigned char *) safe_malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH+1);
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

/* parses a /users request from the client, ensuring that the payload is correct etc. */
int parse_client_users(packet_t *packet, client_parsed_t *parsed) {
  char msg[USERS_MSG_SIZE+1];

  if (!is_packet_legal(packet) || parsed == NULL ||
      parsed->id != C_MSG_USERS)
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

/* sets the pointers of the parsed struct to null for the type of the parsed struct
passed to it */
void initialize_client_parsed(client_parsed_t *p) {
  if (p == NULL)
    return;

  switch (p->id) {
    case C_MSG_EXIT:
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
      break;
    case C_MSG_USERS:
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
      break;
    case C_MSG_USERS:
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
      break;
    case C_MSG_USERS:
      break;
    case C_META_PUBKEY_RQST:
      break;
    default:
      break;
  }

  free(p);
}

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

  parsed = (server_parsed_t *) safe_malloc(sizeof(server_parsed_t));
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

/* parses a packet that contains user data into the respective struct. Both
login success and register success can return a packet that contains user info
which is parsed into the same struct data fields here.
Returns:
-1 on failure
1 on success*/

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

  parsed->user_details.iv = (unsigned char *) safe_malloc(sizeof(unsigned char) * IV_SIZE+1);
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

  parsed->user_details.encrypted_keys =
      (unsigned char *) safe_malloc(sizeof(unsigned char) * parsed->user_details.encrypt_sz+1);
  if (parsed->user_details.encrypted_keys == NULL)
    return -1;

  memcpy(parsed->user_details.encrypted_keys, tmp, parsed->user_details.encrypt_sz);
  parsed->user_details.encrypted_keys[parsed->user_details.encrypt_sz] = '\0';

  return 1;
}

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

  parsed->error_message = (char *) safe_malloc(sizeof(char) * size+1);
  if (parsed->error_message == NULL)
    return -1;

  memcpy(parsed->error_message, packet->payload, size);
  parsed->error_message[size] = '\0';

  return 1;
}

void initialize_server_parsed(server_parsed_t *p) {
  if (p == NULL)
    return;

  switch (p->id) {
    case S_MSG_PUBMSG:
      break;
    case S_MSG_PRIVMSG:
      break;
    case S_MSG_USERS:
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

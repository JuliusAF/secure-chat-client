#include "parse_user_input.h"

/* defines the delimiters used for strtok */
static const char delim[] = " \n\t\v";

/* helper function to print hexadecimals. Not used in final version */
void print_hex(unsigned char *hex, int len) {
  printf("hexadecimals: ");
  for (int i = 0; i < len; i++) {
    printf("%x", hex[i]);
  }
  printf("END\n");
}

/* checks if a string is all digits */
bool is_digit(const char *s) {
  for (size_t i = 0; i < strlen(s); i++)
    if(!isdigit(s[i]))
      return false;
  return true;
}

/* trims the white space at the front of a string */
char* trim_front_whitespace(char* input) {
  if (!input)
    return input;

  char *input_end = input + strlen(input);

  while (isspace(input[0]) && input < input_end)
    input++;

  return input;
}

/* times the white space at the back of a string */
int trim_back_whitespace(char* input) {
  int input_size;

  if (input == NULL || strlen(input) == 0)
    return -1;

  input_size = strlen(input);

  while (isspace(input[input_size-1]) && input_size != 0)
    input_size--;
  input[input_size] = '\0';
  return input_size;
}

/* checks if a message is legal as defined in the 'user interface' section
in the assignment documentation */
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

/* create and error node */
void make_error(command_t *node, char *s) {
  node->command = COMMAND_ERROR;
  node->error_message = safe_strdup(s);
}

/* The following functions are helper functions to
parse_input() that error check user input and if there are no errors,
it places the fields belonging to some input into a node of type command_t*/

/* parse an exit command by the user */
command_t *make_exit_node(char *input) {
  command_t *node = safe_malloc(sizeof *node);

  if (strcmp(input,"/exit") != 0)
    make_error(node, "User input after '/exit'. Incorrect command");
  else
    node->command = COMMAND_EXIT;
  return node;
}

/* parse a login command by the user */
command_t* make_login_node(char *input) {
  command_t *node = safe_malloc(sizeof *node);
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

/* parse a register command by the user. The format is the same as a login, so
it calls the make login node. */
command_t* make_register_node(char *input) {
  command_t *node;
  node = make_login_node(input);
  /* register uses the same syntax and fields as login. Therefore only the type
  has to be changed*/
  if (node->command == COMMAND_LOGIN)
    node->command = COMMAND_REGISTER;

  return node;
}

/* parse a private message by the user */
command_t *make_privmsg_node(char *input) {
  int token_size;
  command_t *node = safe_malloc(sizeof *node);
  char *temp = safe_malloc(strlen(input)+1 * sizeof *temp), *tmp_msg,
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

/* parse a public message by the user */
command_t* make_pubmsg_node(char *input) {
  command_t *node = safe_malloc(sizeof *node);

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

/* parse a users command */
command_t* make_users_node(char *input) {
  command_t *node = safe_malloc(sizeof *node);

  if (strcmp(input,"/users") != 0)
    make_error(node, "User input after 'users'. Incorrect command");
  else {
    node->command = COMMAND_USERS;
  }

  return node;
}

/* calls the appropriate helper function based on first token pull from a string
after it has had its front space and back space cleared */
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

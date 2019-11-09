#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "parser.h"
#include "safe_wrappers.h"

static const char delim[] = " \n\t\v";

char *read_input(int fd) {
  char *input = NULL;
  char buffer[KILOBYTE];
  int bytes_read, input_size = 0;

  do {
    bytes_read = read(fd, buffer, sizeof(buffer));
    if(bytes_read < 0)
      perror("Failed to read input");
    else if(fd == STDIN_FILENO && bytes_read == 0)
      exit(0);
    input = safe_realloc(input, input_size+bytes_read+1);
    memcpy(input+input_size, &buffer, bytes_read);
    input_size += bytes_read;
  } while (bytes_read == KILOBYTE && buffer[KILOBYTE-1] != '\n');

  /*if(input[input_size-1] == '\n')
    input[input_size-1] = '\0';
  else*/
  input[input_size] = '\0';
  return input;
}

char* trim_front_whitespace(char* input) {
  if(!input)
    return input;

  char *input_end = input + strlen(input);

  while(isspace(input[0]) && input < input_end) {
    input++;
  }
  return input;
}

int trim_back_whitespace(char* input) {
  if(!input)
    return -1;

  int input_size = strlen(input);
  printf("input size = %d \n", input_size);

  while(isspace(input[input_size-1]) && input_size != 0) {
    input_size--;
  }
  input[input_size] = '\0';
  return input_size;
}

static bool is_message_legal(char *input) {
  if(input[0] == '/' || input[0] == '@' || input == NULL || input[0] == '\0')
    return false;

  for(size_t i = 0; i < strlen(input); i++) {
    if(input[i] == '\n')
      return false;
  }
  return true;
}

static bool is_token_legal(char *input) {
  if(input == NULL)
    return false;

  for(size_t i = 0; i < strlen(input); i++) {
    if(input[0] == ' ' || input[0] == '\n')
      return false;
  }
  return true;
}

void make_error(command_t *node, char *s) {
  node->command = COMMAND_ERROR;
  node->error_message = safe_strdup(s);
}

command_t *make_exit(char *input) {
  command_t *node = safe_malloc(sizeof(command_t));

  if(strcmp(input,"/exit") != 0) {
    make_error(node, "User input after '/exit'. Incorrect command");
  }
  else {
    node->command = COMMAND_EXIT;
  }
  return node;
}

command_t* make_login(char *input) {
  command_t *node = safe_malloc(sizeof(command_t));
  char *temp = malloc(sizeof(char) * (strlen(input)+1)),
  *token, *username, *password;

  memcpy(temp, input, strlen(input)+1);
  token = strtok(temp, delim);
  token = strtok(NULL, delim);

  if(!is_token_legal(token))
    make_error(node, "Username follows incorrect syntax");
  else if(strlen(token) > USERNAME_MAX)
    make_error(node, "Username larger than 20 characters");
  else {
    username = safe_strdup(token);
    token = strtok(NULL, delim);
    if(token == NULL) {
      make_error(node, "No password provided");
      free(username);
      free(temp);
      return node;
    }
    password = safe_strdup(token);
    token = strtok(NULL, delim);

    if(token != NULL)
      make_error(node, "More user input after account details");
    else if(!is_token_legal(password))
      make_error(node, "Password follows incorrect syntax");
    else if(strlen(password) > PASSWORD_MAX)
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

command_t *make_privmsg(char *input) {
  int token_size;
  command_t *node = safe_malloc(sizeof(command_t));
  char *temp = safe_malloc(sizeof(char)*(strlen(input)+1)), *tmp_msg,
  *token, *username;

  memcpy(temp, input, strlen(input)+1);
  token = strtok(temp, delim);
  token_size = strlen(token);
  if(token == NULL || token_size < 2) {
    make_error(node, "No recipient for private message");
    free(temp);
    return node;
  }

  username = safe_strdup(token+1);

  if(!is_token_legal(username))
    make_error(node, "Impossible recipient name");
  else {
    memcpy(temp, input, strlen(input)+1);
    tmp_msg = temp;
    tmp_msg += token_size;
    tmp_msg = trim_front_whitespace(tmp_msg);
    trim_back_whitespace(tmp_msg);

    if(!is_message_legal(tmp_msg))
      make_error(node, "Message follows incorrect syntax or is empty");
    else if(strlen(tmp_msg) > MESSAGE_MAX)
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

command_t* make_pubmsg(char *input) {
  command_t *node = safe_malloc(sizeof(command_t));

  if(!is_message_legal(input))
    make_error(node, "Message follows incorrect syntax or is empty");
  else if(strlen(input) > MESSAGE_MAX)
    make_error(node, "Message is greater than 200 characters");
  else {
    node->command = COMMAND_PUBMSG;
    node->message = safe_strdup(input);
  }
  return node;
}

command_t* make_register(char *input) {
  command_t *node;
  node = make_login(input);
  if(node->command == COMMAND_LOGIN) {
    node->command = COMMAND_REGISTER;
  }
  return node;
}

command_t* make_users(char *input) {
  command_t *node = safe_malloc(sizeof(command_t));

  if(strcmp(input,"/users") != 0)
    make_error(node, "User input after 'users'. Incorrect command");
  else {
    node->command = COMMAND_USERS;
  }
  return node;
}

command_t *parse_input(char *input) {
  char *formatted_input, *temp, *token;
  command_t *node;

  formatted_input = trim_front_whitespace(input);
  int input_size = trim_back_whitespace(formatted_input);
  if(!formatted_input || input_size < 1)
    return NULL;
  temp = (char *) malloc(sizeof(char) * (strlen(formatted_input)+1));
  memcpy(temp, formatted_input, strlen(formatted_input)+1);
  token = strtok(temp, delim);

  if(strcmp(token,"/exit") == 0)
    node = make_exit(formatted_input);
  else if(strcmp(token,"/login") == 0)
    node = make_login(formatted_input);
  else if(strcmp(token,"/register") == 0)
    node = make_register(formatted_input);
  else if(strcmp(token,"/users") == 0)
    node = make_users(formatted_input);
  else if(token[0] == '@')
    node = make_privmsg(formatted_input);
  else
    node = make_pubmsg(formatted_input);
  free(temp);
  return node;
}

void free_node(command_t *node) {
  if(node == NULL)
    return;

  switch(node->command) {
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

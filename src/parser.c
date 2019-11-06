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
    strcpy(input+input_size, buffer);
    input_size += bytes_read;
  } while (bytes_read == KILOBYTE && buffer[KILOBYTE-1] != '\n');

  if(input[input_size-1] == '\n')
    input[input_size-1] = '\0';
  else
    input[input_size] = '\0';

  return input;
}

char* trim_front_whitespace(char* input) {
  if(!input)
    return input;

  while(isspace(input[0])) {
    input++;
  }
  return input;
}

int trim_back_whitespace(char* input) {
  if(!input)
    return -1;

  int input_size = strlen(input);

  while(isspace(input[input_size-1])) {
    input_size--;
  }
  input[input_size] = '\0';
  return input_size;
}

static bool is_message_legal(char *input) {
  if(input[0] == '/' || input[0] == '@' || input == NULL)
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
    node->error_message = NULL;
  }
  return node;
}

command_t* make_login(char *input) {
  command_t *node = safe_malloc(sizeof(command_t));
  char *temp = malloc(sizeof(char) * (strlen(input)+1)), *token, *username;

  memcpy(temp, input, strlen(input)+1);
  token = strtok(temp, delim);
  token = strtok(NULL, delim);

  if(!is_token_legal(token)) {
    make_error(node, "Username follows incorrect syntax");
  }
  else if(strlen(token) > USERNAME_MAX) {
    make_error(node, "Username larger than 20 characters");
  }
  else {
    username = safe_strdup(token);
    token = strtok(NULL, delim);

    if(!is_token_legal(token))
      make_error(node, "Username follows incorrect syntax");
    else if(strlen(token) > PASSWORD_MAX)
      make_error(node, "Username larger than 20 characters");
    else {
      node->command = COMMAND_LOGIN;
      node->error_message = NULL;
      node->acc_details.username = username;
      node->acc_details.password = safe_strdup(token);
    }
  }

  free(temp);
  free(token);
  return node;
}

command_t* make_privmsg(char *input) {
  command_t *node = safe_malloc(sizeof(command_t));
  char *temp = malloc(sizeof(char) * (strlen(input)+1)), *token, *username;

  memcpy(temp, input, strlen(input)+1);
  token = strtok(temp, delim);
  if(token == NULL || strlen(token) < 2)
    make_error(node, "No recipient for private message");

  token++;
  if(!is_token_legal(token))
    make_error(node, "Impossible recipient name");
  else {
    username = safe_strdup(token);
    memcpy(temp, input, strlen(input)+1);
    temp += strlen(token)+1;
    temp = trim_front_whitespace(temp);

    if(!is_message_legal(temp))
      make_error(node, "Message follows incorrect syntax or is empty");
    else if(strlen(temp) > MESSAGE_MAX)
      make_error(node, "Message is greater than 200 characters");
    else {
      node->command = COMMAND_PRIVMSG;
      node->error_message = NULL;
      node->privmsg.username = username;
      node->privmsg.message = safe_strdup(temp);
    }
  }

  free(temp);
  free(token);
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
    node->error_message = NULL;
    node->pubmsg.message = safe_strdup(input);
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
    node->command = COMMAND_EXIT;
    node->error_message = NULL;
  }
  return node;
}

command_t *parse_input(char *input) {
  printf("a");
  input = trim_front_whitespace(input);
  int input_size = trim_back_whitespace(input);
  printf("b");
  if(!input || input_size < 0) {
    printf("c");
    return NULL;
  }

  char *temp = malloc(sizeof(char) * (strlen(input)+1)), *token;
  command_t *node;
  printf("d");
  memcpy(temp, input, strlen(input)+1);
  token = strtok(temp, delim);
  printf("e");
  if(strcmp(token,"/exit") == 0) {
    printf("f");
    node = make_exit(input);
  }
  else if(strcmp(token,"/login") == 0) {
    printf("g");
    node = make_login(input);
  }
  else if(strcmp(token,"/register") == 0) {
    printf("h");
    node = make_register(input);
  }
  else if(strcmp(token,"/users") == 0) {
    printf("i");
    node = make_users(input);
  }
  else if(token[0] == '@') {
    printf("j");
    node = make_privmsg(input);
  }
  else {
    printf("k");
    node = make_pubmsg(input);
  }
  printf("l");
  free(token);
  free(temp);
  return node;
}

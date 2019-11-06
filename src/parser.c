#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "parser.h"

char* read_input(int fd) {
  char* input = NULL;
  char buffer[MEGABYTE];
  int bytes_read, input_size = 0;

  do {
    bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read < 0) {
      perror("Failed to read input");
    }
    printf("bytes read: %d \n", bytes_read);
    input = realloc(input, input_size+bytes_read);
    strcpy(input+input_size, buffer);
    input_size += bytes_read;
  } while (bytes_read == MEGABYTE && buffer[MEGABYTE-1] != '\n');
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

  int input_size = strlen(input)+1;

  while(isspace(input[input_size-1])) {
    input_size--;
  }
  input[input_size] = '\0';
  return input_size;
}

command_t* construct_command_node(char* input) {
  char* temp,* token;
  command_t* node;
  const char delim[] = " \n\t\v";
  node = (command_t *) malloc(sizeof(command_t));
  temp = (char *) malloc(sizeof(input));
  memcpy(temp, input, strlen(input+1));
  token = strtok(input, delim);
  if(strcmp(token,"/exit") == 0) {

  }
  else if(strcmp(token,"/login") == 0) {

  }
  else if(strcmp(token,"/register") == 0) {

  }
  else if(strcmp(token,"/users") == 0) {

  }
  else if(token[0] == '@') {

  }
  else {

  }
}

command_t* parse_input(char* input) {
  input = trim_front_whitespace(input);
  int input_size = trim_back_whitespace(input);
  if(!input || input_size < 0)
    return NULL;

}

#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define MEGABYTE 5
#define MESSAGE_MAX 200
#define USERNAME_MAX 18
#define PASSWORD_MAX 24

enum command_type {
  COMMAND_EXIT,
  COMMAND_LOGIN,
  COMMAND_PRIVMSG,
  COMMAND_PUBMSG,
  COMMAND_REGISTER,
  COMMAND_USERS,
  COMMAND_ERROR
};

typedef struct inputline {
  enum command_type command;
  char* error_message;

  union {
    struct {
      char username[USERNAME_MAX+1];
      char password[PASSWORD_MAX+1];
    } login;

    struct {
      char username[USERNAME_MAX+1];
      char message[MESSAGE_MAX+1];
    } privmsg;

    struct {
      char message[MESSAGE_MAX+1];
    } pubmsg;

    struct {
      char username[USERNAME_MAX+1];
      char password[PASSWORD_MAX+1];
    } rgster;
  };
} command_t;

char* read_input(int fd);
char* trim_front_whitespace(char* input);
int trim_back_whitespace(char* input);
command_t* construct_command_node(char* input);
command_t* parse_input(char* input);


#endif

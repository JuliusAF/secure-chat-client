#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define KILOBYTE 1024
#define MESSAGE_MAX 200
#define USERNAME_MAX 20
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
      char *username;
      char *password;
    } acc_details;

    struct {
      char *username;
      char *message;
    } privmsg;

    struct {
      char *message;
    } pubmsg;
  };
} command_t;

char *read_input(int fd);
char *trim_front_whitespace(char *input);
int trim_back_whitespace(char *input);
void make_error(command_t *node, char *s);
command_t *make_exit(char* input);
command_t *make_login(char *input);
command_t *make_privmsg(char *input);
command_t *make_pubmsg(char *input);
command_t *make_register(char *input);
command_t *make_users(char *input);
command_t *parse_input(char *input);


#endif

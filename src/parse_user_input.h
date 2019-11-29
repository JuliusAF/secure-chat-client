#ifndef PARSE_USER_INPUT_H
#define PARSE_USER_INPUT_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "network.h"
#include "safe_wrappers.h"

#define CHUNK 10000
#define MESSAGE_MAX 200
#define USERNAME_MAX 20
#define PASSWORD_MAX 24

#define COMMAND_EXIT 0
#define COMMAND_LOGIN 1
#define COMMAND_REGISTER 2
#define COMMAND_PRIVMSG 3
#define COMMAND_PUBMSG 4
#define COMMAND_USERS 5
#define COMMAND_ERROR 6

typedef struct parsed_input {
  int command;

  union {
    /* on a login or register command, the user provides a username and
    password */
    struct {
      char *username;
      char *password;
    } acc_details;

    /* a private message contains the recipient and the message */
    struct {
      char *username;
      char *message;
    } privmsg;

    /* a public message commands contains only a message*/
    char *message;
    /* if the user input is unknown, and error message is place here */
    char* error_message;
  };
} command_t;

/* functions for parsing user input on the client side */
void print_hex(unsigned char *hex, int len);
char *read_input(int fd);
char *trim_front_whitespace(char *input);
int trim_back_whitespace(char *input);
bool is_digit(const char *s);
void make_error_node(command_t *node, char *s);
command_t *make_exit_node(char* input);
command_t *make_login_node(char *input);
command_t *make_privmsg_node(char *input);
command_t *make_pubmsg_node(char *input);
command_t *make_register_node(char *input);
command_t *make_users_node(char *input);
command_t *parse_input(char *input);
bool is_node_legal(command_t *node);
void free_node(command_t *node);

#endif

#ifndef PARSER_H
#define PARSER_H

#include "network.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define CHUNK 10000
#define MESSAGE_MAX 200
#define USERNAME_MAX 20
#define PASSWORD_MAX 24

/* The types of commands are defined as ints
instead of in an enum because it makes it easier to
(de)serialize them and send them over a network*/
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

typedef struct parsed_client_input {
  uint16_t id;

  union {
    /* when sending a registration packet to the server, the following fields
    must be sent */
    struct {
      char *username;
      unsigned char *hash_password;
      unsigned int publen;
      char *pubkey;
      unsigned char *iv;
      unsigned int encrypt_sz;
      unsigned char *encrypted_keys;
    } reg_packet;
    /* a login request packet contains the username and hashed password
    of the person logging in*/
    struct {
      char *username;
      unsigned char *hash_password;
    } log_packet;
  };
} client_parsed_t;

typedef struct parsed_server_input {
  uint16_t id;

  union {
    /* on a successful login or register, the server sends the client the IV
    used to AES encrypt an RSA pair, the size of the encrypted data and the
    encrypted RSA pair */
    struct {
      unsigned char *iv;
      unsigned int encrypt_sz;
      unsigned char *encrypted_keys;
    } user_details;
    /* when an error is sent from server to client, the packet contains
    only an error message in its payload.*/
    char *error_message;
  };
} server_parsed_t;

typedef struct packet_to_send packet_t;

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

/* functions for parsing packets received server side from the client */

client_parsed_t *parse_client_input(packet_t *p);
int parse_client_register(packet_t *packet, client_parsed_t *parsed);
int parse_client_login(packet_t *packet, client_parsed_t *parsed);
int parse_client_users(packet_t *packet, client_parsed_t *parsed);
void initialize_client_parsed(client_parsed_t *p) ;
bool is_client_parsed_legal(client_parsed_t *p);
void free_client_parsed(client_parsed_t *p);

/* functions for parsing packets sent from server to client*/

server_parsed_t *parse_server_input(packet_t *p);
bool is_server_parsed_legal(server_parsed_t *p);
int parse_server_userinfo(packet_t *packet, server_parsed_t *parsed);
int parse_server_error(packet_t *packet, server_parsed_t *parsed);
void initialize_server_parsed(server_parsed_t *p);
bool is_server_parsed_legal(server_parsed_t *p);
void free_server_parsed(server_parsed_t *p);


#endif

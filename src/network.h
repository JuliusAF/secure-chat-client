#ifndef NETWORK_H
#define NETWORK_H

#include "parser.h"

int create_server_socket(unsigned short port);
int client_connect(const char *hostname, unsigned short port);
int accept_connection(int serverfd);
char *serialize_command_struct(command_t *n);
command_t *deserialize_command_struct(char *packet);
char *create_packet(char *data, char *metadata);

#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include "parser.h"
#include "network.h"

int main( int argc, const char* argv[] ) {
	fd_set selectfds, activefds;
	command_t *node;
	char *input, *server_output;
	unsigned short port;
	int socketfd, maxfd, bytes_read;

	if (argc != 3) {
		fprintf(stderr, "Incorrect number of arguments. Must be 2\n");
		return EXIT_FAILURE;
	}
	else if (!is_digit(argv[2])) {
		fprintf(stderr, "Port must be a number\n");
		return EXIT_FAILURE;
	}

	port = (unsigned short) atoi(argv[2]);
	socketfd = client_connect(argv[1], port);
	server_output = (char *) malloc(sizeof(char) * MAX_PACKET_SIZE+1);

	maxfd = (STDIN_FILENO > socketfd) ? STDIN_FILENO : socketfd;
	FD_ZERO(&activefds);
	FD_SET(STDIN_FILENO, &activefds);
	FD_SET(socketfd, &activefds);

	while (true) {
		selectfds = activefds;
		select(maxfd+1, &selectfds, NULL, NULL, NULL);
		if (FD_ISSET(STDIN_FILENO, &selectfds)) {
			input = read_input(STDIN_FILENO);
			node = parse_input(input);

			if (node != NULL && node->command != COMMAND_ERROR)
				write(socketfd, input, strlen(input)+1);
			if (node != NULL && node->command == COMMAND_EXIT) {
				free(node);
				break;
			}
			free(input);
			free(node);
		}
		else if (FD_ISSET(socketfd, &selectfds)) {
			bytes_read = read(socketfd, server_output, MAX_PACKET_SIZE);
			if (bytes_read < 0) {
				perror("failed to read from server socket");
				continue;
			}
			else if (bytes_read == 0) {
				printf("Lost connection to server. Closing client.\n");
				break;
			}
			printf("%s\n", server_output);
		}
	}
	free(input);
	close(socketfd);
	return 0;
}

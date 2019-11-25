#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ssl-nonblock.h"
#include "parser.h"
#include "network.h"
#include "client_utilities.h"

/* I can not get input from output redirection to work, which means that
the test.py file provided also does not work. The problem is that I exit my program
when stdin reaches end of file, and when input is entered from a file,
I'm guessing exiting of the program happens too fast to catch
the data sent from the server since they are all
in the same loop. */

/* Very rudimentary because I do not yet have a fleshed out protocol.*/
int main( int argc, const char* argv[] ) {
	fd_set selectfds, activefds;
	command_t *node;
	char *input, *server_output, input1[500];
	unsigned short port;
	int socketfd, maxfd, bytes_read, loop = 0;

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
	input = (char *) malloc(sizeof(char) * 501);
	server_output = (char *) malloc(sizeof(char) * MAX_PACKET_SIZE+1);

	char cacertpath[] = "ttpkeys/ca-cert.pem";
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_load_verify_locations(ctx, cacertpath, NULL);
  SSL *ssl = SSL_new(ctx);
	SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

  /* configure the socket as non-blocking */
  set_nonblock(socketfd);

  /* set up SSL connection with client and check server certificate*/
  SSL_set_fd(ssl, socketfd);
	if (ssl_block_connect(ssl, socketfd) != 1) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "verify result=%ld\n", SSL_get_verify_result(ssl));
    exit(EXIT_FAILURE);
  }

	maxfd = (STDIN_FILENO > socketfd) ? STDIN_FILENO : socketfd;
	FD_ZERO(&activefds);
	FD_SET(STDIN_FILENO, &activefds);
	FD_SET(socketfd, &activefds);

	while (true) {
		selectfds = activefds;
		select(maxfd+1, &selectfds, NULL, NULL, NULL);

		if (FD_ISSET(STDIN_FILENO, &selectfds)) {
			bytes_read = read_stdin(input1, sizeof(input1));
			if (bytes_read == 0)
				break;

			strcpy(input, input1);
			node = parse_input(input);

			print_parse_error(node);

			if (node != NULL && node->command != COMMAND_ERROR)
				ssl_block_write(ssl, socketfd, input, strlen(input)+1);

			if (node != NULL && node->command == COMMAND_EXIT) {
				free(node);
				break;
			}
			free(node);
		}

		if (FD_ISSET(socketfd, &selectfds) && ssl_has_data(ssl)) {
			bytes_read = ssl_block_read(ssl, socketfd, server_output, MAX_PACKET_SIZE);
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
		loop++;
	}

	SSL_free(ssl);
  SSL_CTX_free(ctx);
	free(server_output);
	free(input);
	close(socketfd);
	return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <time.h>
#include "parser.h"
#include "network.h"
#include "database.h"
#include "server_utilities.h"
#include "safe_wrappers.h"

/* verifies program arguments*/
static void verify_arguments(int argc, const char* argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Incorrect number of arguments. Must be 1\n");
		exit(EXIT_FAILURE);
	}
	else if (!is_digit(argv[1])) {
		fprintf(stderr, "Port must be a number\n");
		exit(EXIT_FAILURE);
	}
}

/* returns the index of the first element
that is labelled false. This index is the first free location
in to_ and from_child where a pipe can be created with pipe()*/
static int first_free_pipe(bool *b) {
	for(int i = 0; i < MAX_CLIENTS; i++)
		if(!b[i])
			return i;
	return -1;
}

/* matches a file descriptor of a pipe to the index
in the array in which the file descriptor is located*/
static int pipe_index(int *pipes, int fd) {
	for(int i = 0; i < MAX_CLIENTS; i++)
		if(pipes[i*2] == fd)
			return i;
	return -1;
}

int main(int argc, const char* argv[]) {
	fd_set selectfds, activefds;
	char pipe_input;
	unsigned short port;
	int serverfd, connfd, free_pipe, to_child[60], from_child[60],
			bytes_read, current_pipe, rc;
	bool active_pipes[30] = {false};
	pid_t pid;

	verify_arguments(argc, argv);

	port = (unsigned short) atoi(argv[1]);
	serverfd = create_server_socket(port);

	rc = initialize_database();
	if (rc < 0) {
		fprintf(stderr, "Failed to initialize database\n");
		close(serverfd);
		exit(EXIT_FAILURE);
	}

	FD_ZERO(&activefds);
	FD_SET(serverfd, &activefds);

	while (true) {
		selectfds = activefds;
		select(FD_SETSIZE, &selectfds, NULL, NULL, NULL);

		for (int i = 0; i < FD_SETSIZE; i++) {
			if (FD_ISSET(i, &selectfds)) {
				if (i == serverfd) {
					free_pipe = first_free_pipe(active_pipes);
					connfd = accept_connection(serverfd);
					if (connfd < 0)
						continue;

					/* denies connections if maximum no of clients is reached. */
					if (free_pipe < 0) {
						fprintf(stderr, "Maximum clients reached\n");
						close(connfd);
						continue;
					}

					if (pipe(to_child + free_pipe*2) < 0) {
						perror("failed to create to_child pipe");
						close(connfd);
						continue;
					}
					else if (pipe(from_child + free_pipe*2) < 0) {
						perror("failed to create from_child pipe");
						close(to_child[free_pipe*2]);
						close(to_child[free_pipe*2+1]);
						close(connfd);
						continue;
					}

					active_pipes[free_pipe] = true;
					pid = fork();
					if (pid == (pid_t) -1) {
						perror("failed to fork child process");
						close(to_child[free_pipe*2+1]);
						close(from_child[free_pipe*2]);
					}
					if (pid == 0) {
						worker(connfd, to_child + free_pipe*2, from_child + free_pipe*2);
						exit(0);
					}

					FD_SET(from_child[free_pipe*2], &activefds);

					close(to_child[free_pipe*2]);
					close(from_child[free_pipe*2+1]);
					close(connfd);
				}
				else {
					current_pipe = pipe_index(from_child, i);
					bytes_read = read(i, &pipe_input, S_MSG_LEN);

					if (bytes_read == 0 ||
							pipe_input == 'C') {
						active_pipes[current_pipe] = false;
						close(i);
						close(to_child[current_pipe*2+1]);
						FD_CLR(i, &activefds);
					}
					else {
						/* notifies all workers that the database is updated. */
						for (int j = 0; j < MAX_CLIENTS; j++) {
							if (active_pipes[j])
								write(to_child[j*2+1], S_MSG_UPDATE, S_MSG_LEN);
						}
					}
				}
			}
		}
	}
	close(serverfd);

	return 0;
}

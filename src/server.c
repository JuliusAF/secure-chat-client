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

static int first_free_pipe(bool *b) {
	for(int i = 0; i < MAX_CLIENTS; i++)
		if(!b[i])
			return i;
	return -1;
}

static int pipe_index(int *pipes, int fd) {
	for(int i = 0; i < MAX_CLIENTS; i++)
		if(pipes[i*2] == fd)
			return i;
	return -1;
}

int main( int argc, const char* argv[] ) {
	fd_set selectfds, activefds;
	char pipe_input[16];
	unsigned short port;
	int serverfd, connfd, free_pipe, to_child[60], from_child[60],
			bytes_read, current_pipe, rc;
	bool active_pipes[30] = {false};
	pid_t pid;
	sqlite3 *db;

	if (argc != 2) {
		fprintf(stderr, "Incorrect number of arguments. Must be 1\n");
		return EXIT_FAILURE;
	}
	else if (!is_digit(argv[1])) {
		fprintf(stderr, "Port must be a number\n");
		return EXIT_FAILURE;
	}

	port = (unsigned short) atoi(argv[1]);
	serverfd = create_server_socket(port);

	db = open_database();
  if (db == NULL) {
		close(serverfd);
		return 1;
	}

	rc = initialize_database(db);
	if (rc < 0) {
		fprintf(stderr, "Failed to initialize database\n");
		sqlite3_close(db);
		close(serverfd);
		return 1;
	}
	
	sqlite3_close(db);

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

					if (free_pipe < 0) {
						fprintf(stderr, "Maximum clients reached\n");
						write(connfd, "Maximum no of clients exceeded", 30);
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
					bytes_read = read(i, pipe_input, 15);

					if (bytes_read == 0 ||
							pipe_input == NULL ||
							strcmp(pipe_input, "Closed") == 0) {
						active_pipes[current_pipe] = false;
						close(i);
						close(to_child[current_pipe*2+1]);
						FD_CLR(i, &activefds);
					}
					else {
						strcpy(pipe_input, "Updated");
						for (int j = 0; j < MAX_CLIENTS; j++) {
							if (active_pipes[j])
								write(to_child[j*2+1], pipe_input, 15);
						}
					}
				}
			}
		}
	}
	close(serverfd);

	return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <time.h>
#include "parser.h"
#include "network.h"
#include "server_utilities.h"
#include "safe_wrappers.h"
#include "database.h"

void worker(int connfd, int from_parent[2], int to_parent[2]) {
	fd_set selectfds, activefds;
	char *input, pipe_input[16], username[USERNAME_MAX+1] = "";
	int maxfd, bytes_read, rc;
	time_t t;
	command_t *node = NULL;

  t = 0;
  input = (char *) safe_malloc(sizeof(char) * MAX_PACKET_SIZE+1);
	close(from_parent[1]);
	close(to_parent[0]);

	maxfd = (connfd > from_parent[0]) ? connfd : from_parent[0];
	FD_ZERO(&activefds);
	FD_SET(connfd, &activefds);
	FD_SET(from_parent[0], &activefds);

	while (true) {
		selectfds = activefds;
		select(maxfd+1, &selectfds, NULL, NULL, NULL);

		if (FD_ISSET(connfd, &selectfds)) {
			bytes_read = read(connfd, input, MAX_PACKET_SIZE);
			if (bytes_read < 0) {
				perror("failed to read bytes");
				continue;
			}
			else if (bytes_read == 0) {
        strcpy(pipe_input, "Closed");
				write(to_parent[1], pipe_input, strlen(pipe_input)+1);
        handle_db_exit(username);
        printf("lost connection\n");
        close(connfd);
				break;
			}

			input[bytes_read] = '\0';
      printf("server user input: %s\n", input);
			node = parse_input(input);
      if (node == NULL)
        continue;

      rc = handle_client_input(node, username, connfd);
      if (rc == 1 || rc == 2) {
        fetch_db_message(username, t, connfd);
        t = time(NULL);
      }
      if (rc == 3 || rc == 4) {
        strcpy(pipe_input, "Updated");
  			write(to_parent[1], pipe_input, strlen(pipe_input)+1);
      }
      else if (rc == 6) {
        strcpy(pipe_input, "Closed");
  			write(to_parent[1], pipe_input, strlen(pipe_input)+1);
        close(connfd);
        break;
      }
			free_node(node);
		}
		if (FD_ISSET(from_parent[0], &selectfds)) {
			read(from_parent[0], pipe_input, 15);
			if(strcmp(pipe_input, "Updated") == 0) {
        fetch_db_message(username, t, connfd);
        t = time(NULL);
			}
		}
	}
	close(from_parent[0]);
	close(to_parent[1]);
	free(input);
}

int handle_client_input(command_t *node, char *user, int connfd) {
  int rc;

  if (node == NULL)
    return -1;

  switch (node->command) {
    case COMMAND_LOGIN:
      rc = handle_db_login(node, user, connfd);
      break;
    case COMMAND_REGISTER:
      rc = handle_db_register(node, user, connfd);
      break;
    case COMMAND_PRIVMSG:
      //rc = handle_db_privmsg(node, user, connfd);
      break;
    case COMMAND_PUBMSG:
      rc = handle_db_pubmsg(node, user, connfd);
      break;
    case COMMAND_USERS:
      //rc = handle_db_users(user, connfd);
      break;
    case COMMAND_EXIT:
      rc = handle_db_exit(user);
      break;
    default:
      break;
  }
  return rc;
}

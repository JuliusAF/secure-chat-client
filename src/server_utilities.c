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

static client_t *initialize_client_info(int connfd) {
  client_t *c = safe_malloc(sizeof(client_t));

  c->connfd = connfd;
  strcpy(c->username, "");
  c->last_updated = 0;

  return c;
}

void worker(int connfd, int from_parent[2], int to_parent[2]) {
	fd_set selectfds, activefds;
	char *input, pipe_input;
	int maxfd, bytes_read, rc;
	command_t *node = NULL;
  client_t *client_info;

  client_info = initialize_client_info(connfd);
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
				write(to_parent[1], S_MSG_CLOSE, S_MSG_LEN);
        handle_db_exit(client_info);
        close(connfd);
				break;
			}

			input[bytes_read] = '\0';
			node = parse_input(input);
      if (node == NULL)
        continue;

      rc = handle_client_input(node, client_info, to_parent[1]);
      if (rc == COMMAND_EXIT) {
        free_node(node);
        break;
      }

			free_node(node);
		}
    /* very rudimentary right now. If the server notifies
    the worker that the database has been updated, the worker
    sends the client all the messages that occurred since it last did
    so. */
		if (FD_ISSET(from_parent[0], &selectfds)) {
			read(from_parent[0], &pipe_input, S_MSG_LEN);
      fetch_db_message(client_info);
		}
	}
	close(from_parent[0]);
	close(to_parent[1]);
  free(client_info);
	free(input);
}

/* This function handles the input from the client. Right now plain text is sent
over the socket and is parsed again using the same parsing function. Once the protocol
is finished, the packet sent from the client will be deserialized. The returned structure is
still of type command_t.*/
int handle_client_input(command_t *node, client_t *client_info, int pipefd) {
  int rc;

  if (node == NULL)
    return -1;

  switch (node->command) {
    case COMMAND_LOGIN:
      rc = handle_db_login(node, client_info);
      if (rc == COMMAND_LOGIN) {
        fetch_db_message(client_info);
      }
      break;
    case COMMAND_REGISTER:
      rc = handle_db_register(node, client_info);
      if (rc == COMMAND_REGISTER) {
        fetch_db_message(client_info);
      }
      break;
    case COMMAND_PRIVMSG:
      //rc = handle_db_privmsg(node, user, connfd);
      break;
    case COMMAND_PUBMSG:
      rc = handle_db_pubmsg(node, client_info);
      if (rc == COMMAND_PUBMSG) {
        write(pipefd, S_MSG_UPDATE, S_MSG_LEN);
      }
      break;
    case COMMAND_USERS:
      //rc = handle_db_users(user, connfd);
      break;
    case COMMAND_EXIT:
      rc = handle_db_exit(client_info);
      if (rc == COMMAND_EXIT) {
        write(pipefd, S_MSG_CLOSE, S_MSG_LEN);
        close(client_info->connfd);
      }
      break;
    default:
      break;
  }
  return rc;
}

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "ssl-nonblock.h"
#include "parser.h"
#include "network.h"
#include "server_utilities.h"
#include "server_network.h"
#include "safe_wrappers.h"
#include "database.h"

static client_t *initialize_client_info(int connfd, SSL *ssl) {
  client_t *c = safe_malloc(sizeof(client_t));

  c->connfd = connfd;
  c->ssl = ssl;
  c->is_logged = false;
  strcpy(c->username, "");
  c->last_updated = 0;

  return c;
}

void worker(int connfd, int from_parent[2], int to_parent[2]) {
	fd_set selectfds, activefds;
	char pipe_input;
  unsigned char *input;
	int maxfd, bytes_read;
  client_t *client_info;
  packet_t *packet;
  client_parsed_t *parsed;

  const char pathcert[] = "serverkeys/server-ca-cert.pem";
  const char pathkey[] = "serverkeys/server-key.pem";
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  SSL *ssl = SSL_new(ctx);
  SSL_use_certificate_file(ssl, pathcert, SSL_FILETYPE_PEM);
  SSL_use_PrivateKey_file(ssl, pathkey, SSL_FILETYPE_PEM);

  set_nonblock(connfd);
  SSL_set_fd(ssl, connfd);
  ssl_block_accept(ssl, connfd);

  client_info = initialize_client_info(connfd, ssl);
	close(from_parent[1]);
	close(to_parent[0]);

	maxfd = (connfd > from_parent[0]) ? connfd : from_parent[0];
	FD_ZERO(&activefds);
	FD_SET(connfd, &activefds);
	FD_SET(from_parent[0], &activefds);

	while (true) {
		selectfds = activefds;
		select(maxfd+1, &selectfds, NULL, NULL, NULL);

		if (FD_ISSET(connfd, &selectfds) && ssl_has_data(ssl)) {
      parsed = NULL;
      packet = NULL;
      input = NULL;

      printf("input from client socket\n");
      input = (unsigned char *) safe_malloc(sizeof(unsigned char) * MAX_PACKET_SIZE);
      if (input == NULL)
        continue;
      bytes_read = read_packet_from_socket(ssl, connfd, input);
			//bytes_read = ssl_block_read(ssl, connfd, input, MAX_PACKET_SIZE);
			if (bytes_read < 0) {
				perror("failed to read bytes");
        free(input);
				continue;
			}
			else if (bytes_read == 0) {
				write(to_parent[1], S_MSG_CLOSE, S_MSG_LEN);
        handle_db_exit(client_info);
        close(connfd);
				break;
			}
      printf("number of bytes read = %d\n", bytes_read);
      //write(1, input, bytes_read);
      //printf("\n");

      packet = unpack_packet(input, bytes_read);
      if (packet == NULL)
        goto cleanup;

      printf("util packet header size = %d\n", packet->header->pckt_sz);
      printf("util packet header id = %d\n", packet->header->pckt_id);

      parsed = parse_client_input(packet);
      if (parsed == NULL)
        goto cleanup;


      printf("util parsed id = %d\n", parsed->id);
      handle_client_input(parsed, client_info, to_parent[1]);

      cleanup:

      free_client_parsed(parsed);
      free_packet(packet);
      free(input);
		}
    /* If the server notifies
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
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  free(client_info);
	free(input);
}

void handle_client_input(client_parsed_t *p, client_t *client_info, int pipefd) {

  if (!is_client_parsed_legal(p))
    return;

  switch (p->id) {
    case C_MSG_EXIT:
      break;
    case C_MSG_LOGIN:
      handle_client_login(p, client_info, S_META_LOGIN_FAIL);
      break;
    case C_MSG_REGISTER:
      handle_client_login(p, client_info, S_META_REGISTER_FAIL);
      //handle_client_register(p, client_info);
      break;
    case C_MSG_PRIVMSG:
      break;
    case C_MSG_PUBMSG:
      break;
    case C_MSG_USERS:
      break;
    case C_META_PUBKEY_RQST:
      break;
    default:
      break;
  }
}

/*
void handle_client_register(client_parsed_t *p, client_t *client_info) {
  int ret;
  char err[300] = "";
  packet_t *packet = NULL;
  fetched_userinfo_t *fetched = NULL;

  if (!is_client_parsed_legal(p) || client_info == NULL)
    return;

  ret = handle_db_register(p, client_info, err);
  printf("handle register return value: %d\n", ret);
  if (ret < 0) {
    packet = gen_s_error_packet(S_META_REGISTER_FAIL, err);
    ret = send_packet_over_socket(client_info->ssl, client_info->connfd, packet);
    if (ret < 1)
  		fprintf(stderr, "failed to send user register error packet\n");
    return;
  }
  else if (ret == 0)
    return;
  //create register packet
  fetched = fetch_db_user_info(client_info);
  if (!is_fetched_userinfo_legal(fetched)) {
    fprintf(stderr, "failed to fetch register user data\n");
    goto cleanup;
  }
  packet = gen_s_userinfo_packet(fetched, S_META_REGISTER_PASS);
  ret = send_packet_over_socket(client_info->ssl, client_info->connfd, packet);
  if (ret < 1)
    fprintf(stderr, "failed to send user register info packet\n");

  cleanup:

  free_fetched_userinfo(fetched);
} */

void handle_client_login(client_parsed_t *p, client_t *client_info, uint16_t id) {
  int ret;
  uint16_t succ_id = 0;
  char err[300] = "";
  packet_t *packet = NULL;
  fetched_userinfo_t *fetched = NULL;

  if (!is_client_parsed_legal(p) || client_info == NULL)
    return;

  if (id == S_META_REGISTER_FAIL) {
    ret = handle_db_register(p, client_info, err);
    succ_id = S_META_REGISTER_PASS;
  }
  else if (id == S_META_LOGIN_FAIL) {
    ret = handle_db_login(p, client_info, err);
    succ_id = S_META_LOGIN_PASS;
  }
  else
    return;

  printf("handle register return value: %d\n", ret);
  if (ret < 0) {
    packet = gen_s_error_packet(id, err);
    ret = send_packet_over_socket(client_info->ssl, client_info->connfd, packet);
    if (ret < 1)
  		fprintf(stderr, "failed to send user register error packet\n");
    return;
  }
  else if (ret == 0)
    return;
  //create register packet
  fetched = fetch_db_user_info(client_info);
  if (!is_fetched_userinfo_legal(fetched)) {
    fprintf(stderr, "failed to fetch register user data\n");
    goto cleanup;
  }
  packet = gen_s_userinfo_packet(fetched, succ_id);
  ret = send_packet_over_socket(client_info->ssl, client_info->connfd, packet);
  if (ret < 1)
    fprintf(stderr, "failed to send user register info packet\n");

  cleanup:

  free_fetched_userinfo(fetched);
}

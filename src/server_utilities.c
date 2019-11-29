#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sqlite3.h>
#include <time.h>
#include <openssl/err.h>
#include "ssl-nonblock.h"
#include "network.h"
#include "server_utilities.h"
#include "server_network.h"
#include "safe_wrappers.h"
#include "database.h"
#include "parse_client_input.h"

/* initializes all variables in a client_t struct*/
static client_t *initialize_client_info(int connfd, SSL *ssl) {
  client_t *c = safe_malloc(sizeof(client_t));

  c->connfd = connfd;
  c->ssl = ssl;
  c->is_logged = false;
  strcpy(c->username, "");
  c->publen = 0;
  c->pubkey = NULL;
  c->last_updated = 0;

  return c;
}

/* frees a client_t struct */
static void free_client_info(client_t *c) {
  if (c == NULL)
    return;

  free(c->pubkey);
  free(c);
}

/* Depending on what packet is sent, the client/user needs to either be logged in
or not logged in for the server to process the request i.e a user that is logged in
cannot login or register again. This function checks whether for a given packet
this login condition is satisfied. If an error is found, an error packet is created
and sent to the client.
Note that these checks are also made on the client side, so this is not strictly
necessary. Only should a different client program be used would these checks matter
Returns:
true if condition is met
false otherwise*/
static bool is_login_cond_satisfied(packet_t *p, client_t *c) {
  int ret = 1;
  packet_t *err_p;

  if (!is_packet_legal(p) || c == NULL)
    false;

  switch (p->header->pckt_id) {
    case C_MSG_EXIT:
      break;
    case C_MSG_LOGIN:
      if (c->is_logged)
        ret = -1;
      break;
    case C_MSG_REGISTER:
      if (c->is_logged)
        ret = -2;
      break;
    case C_MSG_PRIVMSG:
      if (!c->is_logged)
        ret = -3;
      break;
    case C_MSG_PUBMSG:
      if (!c->is_logged)
        ret = -3;
      break;
    case C_MSG_USERS:
      if (!c->is_logged)
        ret = -3;
      break;
    case C_META_PUBKEY_RQST:
      if (!c->is_logged)
        ret = -3;
      break;
    default:
      break;
  }
  /* creates the error packet depending on what error occured. If no error occured
  true is returned, otherwise false */
  switch (ret) {
    case -1:
      err_p = gen_s_error_packet(S_META_LOGIN_FAIL, "user is already logged in");
      break;
    case -2:
      err_p = gen_s_error_packet(S_META_REGISTER_FAIL, "user is already logged in");
      break;
    case -3:
      err_p = gen_s_error_packet(S_MSG_GENERIC_ERR, "user is not currently logged in");
      break;
    default:
      return true;
  }
  send_packet_over_socket(c->ssl, c->connfd, err_p);
  return false;
}

/* worker function that creates the ssl connection using the connfd and
contains the logic of parsing user data and sending packets etc. */
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

      input = safe_malloc(sizeof(unsigned char) * MAX_PACKET_SIZE);
      if (input == NULL)
        continue;
      bytes_read = read_packet_from_socket(ssl, connfd, input);
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

      packet = unpack_packet(input, bytes_read);
      if (packet == NULL)
        goto cleanup;

      if (!is_login_cond_satisfied(packet, client_info)) {
        fprintf(stderr, "login condition not satisfied\n");
        goto cleanup;
      }
      else if (!is_client_sig_good(packet, client_info)) {
        fprintf(stderr, "bad packet signature\n");
        goto cleanup;
      }

      printf("packet id: %d\n", packet->header->pckt_id);
      parsed = parse_client_input(packet);
      if (parsed == NULL)
        goto cleanup;

      printf("reaches handle function\n");

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
		}
	}

	close(from_parent[0]);
	close(to_parent[1]);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  free_client_info(client_info);
	free(input);
}

/* checks if a provided packet is signed properly. No signature verification is done
on register or login attempts as the client themselves have not verified themselves. The
exit command is also not checked as it is not transmitted over the network here.
It is the hash of the payload that is verified.
Returns:
true if packet is login/register/exit or if signature verifies
false on signature verification failure or errors */
bool is_client_sig_good(packet_t *p, client_t *c) {
  bool ret;
  uint16_t id;
  unsigned int publen;
  unsigned char *hash = NULL;
	char *pubkey;
	BIO *bio;
  EVP_PKEY *key;
  RSA *rsa;

  if (!is_packet_legal(p) || c == NULL)
    return false;

  id = p->header->pckt_id;
  publen = c->publen;
  pubkey = c->pubkey;
  /* the packets pertaining to the following three packet ids are never signed
  by the client, and thus are not verified */
  if (id == C_MSG_LOGIN || id == C_MSG_REGISTER ||
      id == C_MSG_EXIT)
    return true;

  key = EVP_PKEY_new();
  /* hash the payload. The hashed payload is what was originally signed */
  hash = hash_input( (char *) p->payload, p->header->pckt_sz);

  bio = BIO_new_mem_buf(pubkey, publen);
  rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
  EVP_PKEY_assign_RSA(key, rsa);

  ret = rsa_verify_sha256(key, p->header->sig, hash, p->header->siglen, SHA256_DIGEST_LENGTH);

  BIO_free(bio);
  free(hash);
  return ret;
}

void handle_client_input(client_parsed_t *p, client_t *client_info, int pipefd) {

  if (!is_client_parsed_legal(p))
    return;
  if (pipefd == 0)
    printf("meme");

  switch (p->id) {
    case C_MSG_EXIT:
      break;
    case C_MSG_LOGIN:
      handle_client_login(p, client_info);
      break;
    case C_MSG_REGISTER:
      handle_client_login(p, client_info);
      break;
    case C_MSG_PRIVMSG:
      break;
    case C_MSG_PUBMSG:
      break;
    case C_MSG_USERS:
      handle_client_users(p, client_info);
      break;
    case C_META_PUBKEY_RQST:
      break;
    default:
      break;
  }
}

void handle_client_login(client_parsed_t *p, client_t *client_info) {
  int ret;
  uint16_t succ_id = 0, fail_id;
  char err[300] = "";
  packet_t *packet = NULL;
  fetched_userinfo_t *fetched = NULL;

  if (!is_client_parsed_legal(p) || client_info == NULL)
    return;

  /* assigns the relevant packet id codes depending on whether the client
  command was login or register */
  if (p->id == C_MSG_REGISTER) {
    ret = handle_db_register(p, client_info, err);
    succ_id = S_META_REGISTER_PASS;
    fail_id = S_META_REGISTER_FAIL;
  }
  else if (p->id == C_MSG_LOGIN) {
    ret = handle_db_login(p, client_info, err);
    succ_id = S_META_LOGIN_PASS;
    fail_id = S_META_LOGIN_FAIL;
  }
  else
    return;

  /* if ret < 0 there was a verification error. This error is sent to client */
  if (ret < 0) {
    packet = gen_s_error_packet(fail_id, err);
    send_packet_over_socket(client_info->ssl, client_info->connfd, packet);
    return;
  }
  /* a return value of 0 implies a some database or memory error. The client
  is notified in this case too */
  else if (ret == 0){
    packet = gen_s_error_packet(fail_id, "database failure");
    send_packet_over_socket(client_info->ssl, client_info->connfd, packet);
    return;
  }

  /* fetch the user info for the user */
  fetched = fetch_db_user_info(client_info);
  if (!is_fetched_userinfo_legal(fetched)) {
    /* another instance of database failure that the client must be made aware of */
    packet = gen_s_error_packet(fail_id, "database failure");
    send_packet_over_socket(client_info->ssl, client_info->connfd, packet);
    goto cleanup;
  }
  /* generate packet and send */
  packet = gen_s_userinfo_packet(fetched, succ_id);
  ret = send_packet_over_socket(client_info->ssl, client_info->connfd, packet);
  if (ret < 1)
    fprintf(stderr, "failed to send user info packet\n");

  cleanup:

  free_fetched_userinfo(fetched);
}

void handle_client_users(client_parsed_t *p, client_t *client_info) {
  int ret;
  char *fetched;
  packet_t *packet;

  if (p == NULL || client_info == NULL ||
      p->id != C_MSG_USERS)
    return;

  if (!client_info->is_logged) {
    packet = gen_s_error_packet(S_MSG_GENERIC_ERR, "user is not currently logged in");
    send_packet_over_socket(client_info->ssl, client_info->connfd, packet);
  }

  fetched = fetch_db_users();
  if (fetched == NULL)
    return;

  packet = gen_s_users_packet(fetched);
  ret = send_packet_over_socket(client_info->ssl, client_info->connfd, packet);
  if (ret < 1)
    fprintf(stderr, "failed to send user info packet\n");

  free(fetched);
}

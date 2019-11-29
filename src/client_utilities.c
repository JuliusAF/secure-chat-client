#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include "cryptography.h"
#include "network.h"
#include "safe_wrappers.h"
#include "client_utilities.h"
#include "client_network.h"
#include "parse_user_input.h"
#include "parse_server_input.h"

/* Initializes the struct that holds the information of the user
logged into the current instance of the client application*/
user_t *initialize_user_info(SSL *ssl, int connfd) {
	if (ssl == NULL)
		return NULL;

	user_t *user = safe_malloc(sizeof(user_t));
	if (user == NULL)
		return NULL;

	user->is_logged = false;
	user->ssl = ssl;
	user->connfd = connfd;
	strcpy(user->username, "");
	memset(user->masterkey, '\0', MASTER_KEY_LEN+1);
	user->rsa_keys = NULL;

	return user;
}

/* initializes and returns request struct*/
request_t *initialize_request(void) {
	request_t *r = safe_malloc(sizeof(request_t));
	if (r == NULL)
		return NULL;

	r->is_request_active = false;
	strcpy(r->username, "");
	memset(r->masterkey, '\0', MASTER_KEY_LEN+1);

	return r;
}

/* function reads input of fixed size from stdin*/
int read_stdin(char *buffer, int size) {
	int bytes_read = 0, index = 0;
	char c;

	if (buffer == NULL || size == 0) {
		return -1;
	}

	while (read(STDIN_FILENO, &c, 1) == 1 && index < size-1) {
		bytes_read++;

		if (c == '\n') {
			buffer[index] = '\0';
			return bytes_read;
		}
		buffer[index] = c;
		index++;
	}

	buffer[index] = '\0';
	return bytes_read;
}

/* creates a date string from a given time_t struct */
int create_date_string(char *date, time_t t) {
	struct tm *tmp;

	if (t < 0) {
		perror("time(null) failed");
		return -1;
	}
  /* Code taken from example supplied by the linux man page on strftime*/
  tmp = localtime(&t);

  if (tmp == NULL) {
    perror("localtime");
    return -1;
  }
  if (strftime(date, 60, DATE_FORMAT, tmp) == 0) {
    fprintf(stderr, "strftime returned 0");
    return -1;
  }
  return 1;
}

/* Takes as input a buffer, a parsed command and the user info. If the command is a private
or public message, it concatenates the fields for the corresponding message
into one string and stores it in the buffer.*/
int create_formatted_msg(char *dest, command_t *n, user_t *u) {
	char date[60];
	int ret;

	ret = create_date_string(date, time(NULL));
	if (ret < 1 || strlen(date) > 59)
		return -1;

	strcpy(dest, "");
	strcpy(dest, date);
	strncat(dest, " ", 1);
	strncat(dest, u->username, strlen(u->username));
	if(n->command == COMMAND_PRIVMSG) {
    strncat(dest, ": @", 3);
    strncat(dest, n->privmsg.username, strlen(n->privmsg.username));
    strncat(dest, " ", 1);
		strncat(dest, n->privmsg.message, strlen(n->privmsg.message));
  }
  else {
    strncat(dest, ": ", 2);
		strncat(dest, n->message, strlen(n->message));
  }

	return 1;
}

/* signs a packet sent from client to server. This only works if the user is logged
in and has a proper private key. Signing a packet in this case refers to
signing the hash of the payload of the packet and storing that signature, as well as the
signature length, in the packet header
Only commands that require the user be logged in are signed. This means the /users
command, as well as a public or pivate message will be signed. A login or register
request will no be signed */
void sign_client_packet(packet_t *p, user_t *u) {
	int ret, privlen;
	char *privkey;
	unsigned char *hash = NULL;
	BIO *bio;
	EVP_PKEY *key;

	if (!is_packet_legal(p) || u == NULL ||
			!u->is_logged || !is_keypair_legal(u->rsa_keys))
		return;

	/* it is the hash of the payload that is signed. As such, the payload is hashed
	here */
	hash = hash_input( (char *) p->payload, p->header->pckt_sz);
	if (hash == NULL)
		return;

	privlen = u->rsa_keys->privlen;
	privkey = u->rsa_keys->privkey;

	bio = BIO_new_mem_buf(privkey, privlen);
	if (bio == NULL)
		goto cleanup;

	key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);

	ret = rsa_sign_sha256(key, p->header->sig, hash, SHA256_DIGEST_LENGTH);
	if (ret == 0) {
		memset(p->header->sig, '\0', MAX_SIG_SZ);
	}
	else
		p->header->siglen = ret;


	cleanup:

	free(hash);
}

/* this function handles the user input dependent on how it was parsed.
From this function, the packets for each command are created and sent
to the server*/
void handle_user_input(command_t *n, user_t *u, request_t *r) {
	if (n == NULL)
    return;

  switch (n->command) {
    case COMMAND_LOGIN:
			handle_user_login(n, u, r);
      break;
    case COMMAND_REGISTER:
			handle_user_register(n, u, r);
      break;
    case COMMAND_PRIVMSG:
			if (!u->is_logged) {
				print_error("you must be logged in to send a private message");
				break;
			}
      break;
    case COMMAND_PUBMSG:
			if (!u->is_logged) {
				print_error("you must be logged in to send a public message");
				break;
			}
      break;
    case COMMAND_USERS:
			handle_user_users(n, u);
      break;
    case COMMAND_EXIT:
      break;
		case COMMAND_ERROR:
			print_error(n->error_message);
			break;
    default:
      break;
  }
}

/* handles a register request. This includes reporting errors that can be
discovered client side, packaging packets and sending them to the server */
void handle_user_register(command_t *node, user_t *user, request_t *request) {
	int ret;
	unsigned char *masterkey;
	packet_t *packet;

	if (node == NULL || node->command != COMMAND_REGISTER)
		return;
	if (user->is_logged) {
		print_error("you cannot register a new account while logged in");
		return;
	}
	if (request->is_request_active) {
		print_error("there is already an active register request");
		return;
	}
	 /* inputs data calculated when the command is invoked, like the masterkey and
	 the username the user entered */
	strncpy(request->username, node->acc_details.username, strlen(node->acc_details.username));
	masterkey = gen_master_key(node->acc_details.username, node->acc_details.password);
	if (masterkey == NULL)
		return;

	memcpy(request->masterkey, masterkey, MASTER_KEY_LEN+1);
	free(masterkey);

	packet = gen_c_register_packet(node, request);
	if (packet == NULL)
		return;

	/* if there were no errors, the register request was successfully sent to
	the server */
	ret = send_packet_over_socket(user->ssl, user->connfd, packet);
	if (ret < 1)	{
		fprintf(stderr, "failed to send user register packet\n");
	}
	else
		request->is_request_active = true;
}

/* handles a login request from the user. Checks for any possible client side
issues such as already being logged in. If all checks pass, the request struct
is updated and a login packet is sent to the server */
void handle_user_login(command_t *node, user_t *user, request_t *request) {
	int ret;
	unsigned char *masterkey;
	packet_t *packet;

	if (node == NULL || user == NULL || request == NULL)
		return;

	if (request->is_request_active) {
		print_error("there is already an active register request");
		return;
	}
	if (user->is_logged) {
		print_error("client is already logged in");
		return;
	}

	/* inputs data calculated when the command is invoked, like the masterkey and
	the username the user entered */
	strncpy(request->username, node->acc_details.username, strlen(node->acc_details.username));
	masterkey = gen_master_key(node->acc_details.username, node->acc_details.password);
	if (masterkey == NULL)
	 return;

	memcpy(request->masterkey, masterkey, MASTER_KEY_LEN+1);
	free(masterkey);

	packet = gen_c_login_packet(node);
	if (packet == NULL)
		return;

	/* if there were no errors, the register request was successfully sent to
	the server */
	ret = send_packet_over_socket(user->ssl, user->connfd, packet);
	if (ret < 1)	{
		fprintf(stderr, "failed to send user register packet\n");
	}
	else
		request->is_request_active = true;

}

/* handles a /users command from user input. This function also signs the
packet */
void handle_user_users(command_t *node, user_t *user) {
	int ret;
	packet_t *packet;

	if (node == NULL || user == NULL ||
			node->command != COMMAND_USERS)
		return;

	if (!user->is_logged) {
		print_error("user is not currently logged in");
		return;
	}

	packet = gen_c_users_packet(node);
	if (packet == NULL)
		return;

	sign_client_packet(packet, user);
	ret = send_packet_over_socket(user->ssl, user->connfd, packet);
	if (ret < 1)	{
		fprintf(stderr, "failed to send user /users packet\n");
	}
}




/* prints a custom error message*/
void print_error(char *s) {
	if (s == NULL)
		return;

	printf("error: %s\n", s);
}

/* these functions deal with input from the server. This includes storing
data obtained from the server if necessary and printing messages */

/* takes as input client side meta data and the parsed input from the server
socket and acts on the information accordingly */
void handle_server_input(server_parsed_t *p, user_t *u, request_t *r) {
	switch (p->id) {
    case S_MSG_PUBMSG:
      break;
    case S_MSG_PRIVMSG:
      break;
    case S_MSG_USERS:
      break;
    case S_MSG_GENERIC_ERR:
      break;
    case S_META_LOGIN_PASS:
			handle_server_log_pass(p, u, r);
      break;
    case S_META_LOGIN_FAIL:
			handle_server_log_fail(p, u, r);
      break;
    case S_META_REGISTER_PASS:
			handle_server_log_pass(p, u, r);
      break;
    case S_META_REGISTER_FAIL:
			handle_server_log_fail(p, u, r);
      break;
    default:
      break;
  }

}

/* this function handles packets sent from the server on register or login
success. In both these instances the same data is returned, so this function can */
void handle_server_log_pass(server_parsed_t *p, user_t *u, request_t *r) {
	int decrypt_sz, encrypt_sz;
	unsigned char decrypted_keys[CHUNK], *encrypted_keys, *iv,
	*masterkey;
	keypair_t *keys = NULL;

	if (!is_server_parsed_legal(p) ||
			u == NULL || r == NULL ||
			(p->id != S_META_LOGIN_PASS &&
			p->id != S_META_REGISTER_PASS))
		return;
	if (!r->is_request_active) {
		fprintf(stderr, "No active register request\n");
		return;
	}
	if (u->is_logged) {
		fprintf(stderr, "user is already logged in, can't process registration\n");
		return;
	}

	iv = p->user_details.iv;
	encrypt_sz = p->user_details.encrypt_sz;
	encrypted_keys = p->user_details.encrypted_keys;
	masterkey = r->masterkey;

	if (encrypt_sz > CHUNK)
		fprintf(stderr, "encrypted keys too large, can't decrypt\n");

	decrypt_sz = apply_aes(decrypted_keys, encrypted_keys, encrypt_sz, masterkey, iv, DECRYPT);
	if (decrypt_sz < 0) {
		fprintf(stderr, "failed to decrypt encrypted keys\n");
	}

	keys = deserialize_keypair(decrypted_keys, decrypt_sz);
	if (keys == NULL)
		return;

	/* copies the necessary fields into the user info struct */
	memcpy(u->username, r->username, USERNAME_MAX);
	u->username[USERNAME_MAX] = '\0';
	memcpy(u->masterkey, r->masterkey, MASTER_KEY_LEN);
	u->masterkey[MASTER_KEY_LEN] = '\0';
	u->rsa_keys = keys;
	u->is_logged = true;
	r->is_request_active = false;

	if (p->id == S_META_LOGIN_PASS)
		printf("authentification succeeded\n");
	else if (p->id == S_META_REGISTER_PASS)
		printf("registration succeeded\n");
}

/* handles any packet that indicates that an attempt to register or login
has failed. If this is the case, the active request is cleared */
void handle_server_log_fail(server_parsed_t *p, user_t *u, request_t *r) {
	if (!is_server_parsed_legal(p) ||
			u == NULL || r == NULL ||
			(p->id != S_META_REGISTER_FAIL &&
			 p->id != S_META_LOGIN_FAIL))
		return;

	if (!r->is_request_active){
		fprintf(stderr, "no active login/register request\n");
		return;
	}

	r->is_request_active = false;
	strcpy(r->username, "");
	memset(r->masterkey, '\0', MASTER_KEY_LEN+1);

	print_error(p->error_message);
}

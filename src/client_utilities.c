#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include "cryptography.h"
#include "network.h"
#include "safe_wrappers.h"
#include "parser.h"
#include "client_utilities.h"
#include "client_network.h"


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

/* this function handles the user input dependent of how it was parsed.
From this function, the packets for each command are created and sent
to the server*/
void handle_user_input(command_t *n, user_t *u, request_t *r) {
	if (n == NULL)
    return;

  switch (n->command) {
    case COMMAND_LOGIN:
			if (u->is_logged) {
				print_error("client already logged in");
				break;
			}
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
			if (!u->is_logged) {
				print_error("user is not currently logged in");
				break;
			}
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
	printf("reached handle server input\n");
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
      break;
    case S_META_REGISTER_PASS:
			handle_server_log_pass(p, u, r);
      break;
    case S_META_REGISTER_FAIL:
      break;
    default:
      break;
  }

}

void handle_server_log_pass(server_parsed_t *p, user_t *u, request_t *r) {
	printf("reached handle log pass\n");
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

	printf("private key: %s\n", keys->privkey);
	printf("public key: %s\n", keys->pubkey);

	if (strlen(r->username) > USERNAME_MAX)
		return;
	strncpy(u->username, r->username, strlen(r->username));
	memcpy(u->masterkey, r->masterkey, MASTER_KEY_LEN);
	u->masterkey[MASTER_KEY_LEN] = '\0';
	u->rsa_keys = keys;
	u->is_logged = true;
	r->is_request_active = false;

}

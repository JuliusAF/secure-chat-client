#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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

	user_t *user = safe_malloc(sizeof *user);
	if (user == NULL)
		return NULL;

	user->is_logged = false;
	user->ssl = ssl;
	user->connfd = connfd;
	memset(user->username, '\0', USERNAME_MAX+1);
	memset(user->masterkey, '\0', MASTER_KEY_LEN+1);
	user->rsa_keys = NULL;

	return user;
}

/* initializes and returns request struct*/
request_t *initialize_request(void) {
	request_t *r = safe_malloc(sizeof *r);
	if (r == NULL)
		return NULL;

	r->is_request_active = false;
	memset(r->username, '\0', USERNAME_MAX+1);
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

/* signs a packet sent from client to server. This only works if the user is logged
in and has a proper private key. Signing a packet in this case refers to
signing the hash of the payload of the packet and storing that signature, as well as the
signature length, in the packet header
Only commands that require the user be logged in are signed. This means the /users
command, as well as a public or pivate message will be signed. A login or register
request will not be signed */
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

/* this function verifies another clients signature. This signature may be its own.
The signature is transmitted as part of a message (public or private) */
bool verify_client_payload(char *cert, unsigned int certlen, char* sender,
													unsigned char *s, unsigned int slen, unsigned char *hash) {
	bool ret = false;
	char *pubkey;
	unsigned int publen;
	BIO *bio;
	EVP_PKEY *key;

	if (cert == NULL || sender == NULL || s == NULL || hash == NULL)
		return false;

	/* verify authenticity of certificate*/
	ret = verify_x509_certificate(cert, certlen, sender);
	if (!ret)
		return false;

	/* obtains public key from certificate */
	pubkey = obtain_pubkey_from_x509(cert, certlen, &publen);
	if (pubkey == NULL)
		return false;

	/* places public key into an EVP_PKEY structure and verifies the signature with it */
	bio = BIO_new_mem_buf(pubkey, publen);
	if (bio == NULL)
		return false;

  key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

  ret = rsa_verify_sha256(key, s, hash, slen, SHA256_DIGEST_LENGTH);

	free(pubkey);
	BIO_free(bio);
  return ret;
}

/* this function handles the user input dependent on how it was parsed.
From this function, the packets for each command are created and sent
to the server*/
void handle_user_input(command_t *n, user_t *u, request_t *r) {
	if (n == NULL || u == NULL || r == NULL)
    return;

  switch (n->command) {
    case COMMAND_LOGIN:
			handle_user_login(n, u, r);
      break;
    case COMMAND_REGISTER:
			handle_user_register(n, u, r);
      break;
    case COMMAND_PRIVMSG:
			handle_user_privmsg(n, u);
      break;
    case COMMAND_PUBMSG:
			handle_user_pubmsg(n, u);
      break;
    case COMMAND_USERS:
			handle_user_users(n, u);
      break;
    case COMMAND_EXIT:
			/* the exit commands requires the breaking of the main loop int client.c As such it is
			handled there */
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
	strncpy(request->username, node->acc_details.username, strnlen(node->acc_details.username, USERNAME_MAX+1));
	masterkey = gen_master_key(node->acc_details.username, node->acc_details.password);
	if (masterkey == NULL)
		return;

	memcpy(request->masterkey, masterkey, MASTER_KEY_LEN+1);
	free(masterkey);

	/* generate the packet to send */
	packet = gen_c_register_packet(node, request);
	if (packet == NULL) {
		fprintf(stderr, "failed to create packet\n");
		return;
	}

	/* if there were no errors, the register request was successfully sent to
	the server */
	ret = send_packet_over_socket(user->ssl, user->connfd, packet);
	if (ret < 1)	{
		fprintf(stderr, "failed to send register request\n");
	}
	else
		request->is_request_active = true;
}

/* handles a login request from the user. Checks for any possible client side
issues such as already being logged in. If all checks pass, the request struct
is updated and a login packet is sent to the server */
void handle_user_login(command_t *node, user_t *user, request_t *request) {
	int ret;
	unsigned char *masterkey = NULL;
	packet_t *packet = NULL;

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
	strncpy(request->username, node->acc_details.username, strnlen(node->acc_details.username, USERNAME_MAX+1));
	masterkey = gen_master_key(node->acc_details.username, node->acc_details.password);
	if (masterkey == NULL)
	 return;

	memcpy(request->masterkey, masterkey, MASTER_KEY_LEN+1);
	free(masterkey);

	packet = gen_c_login_packet(node);
	if (packet == NULL) {
		fprintf(stderr, "failed to create packet\n");
		return;
	}

	/* if there were no errors, the register request was successfully sent to
	the server */
	ret = send_packet_over_socket(user->ssl, user->connfd, packet);
	if (ret < 1)	{
		fprintf(stderr, "failed to send login request\n");
	}
	else
		request->is_request_active = true;

}

/* handles a /users command from user input. This function also signs the
packet */
void handle_user_users(command_t *node, user_t *user) {
	int ret;
	packet_t *packet = NULL;

	if (!user->is_logged) {
		print_error("user is not currently logged in");
		return;
	}

	packet = gen_c_users_packet(node);
	if (packet == NULL) {
		fprintf(stderr, "failed to create packet\n");
		return;
	}

	sign_client_packet(packet, user);
	ret = send_packet_over_socket(user->ssl, user->connfd, packet);
	if (ret < 1)	{
		fprintf(stderr, "failed to send user request\n");
	}

}

/* This function handles the construction of a public message packet */
void handle_user_pubmsg(command_t *node, user_t *user) {
	int ret;
	packet_t *packet = NULL;

	if (!user->is_logged) {
		print_error("you must be logged in to send a public message");
		return;
	}

	packet = gen_c_pubmsg_packet(node, user);
	if (packet == NULL) {
		fprintf(stderr, "failed to create packet\n");
		return;
	}

	sign_client_packet(packet, user);
	ret = send_packet_over_socket(user->ssl, user->connfd, packet);
	if (ret < 1)	{
		fprintf(stderr, "failed to send public message\n");
	}

}

/* creates a public key request packet to send to the user. If a public key is returned
the actual encryption of the private message is handled in the handle_server_pubkey_rqst function */
void handle_user_privmsg(command_t *node, user_t *user) {
	int ret;
	packet_t *packet = NULL;

	if (!user->is_logged) {
		print_error("you must be logged in to send a private message");
		return;
	}
	else if (strncmp(node->privmsg.username, user->username, USERNAME_MAX) == 0) {
		print_error("you can not send a private message to yourself");
		return;
	}

	packet = gen_c_pubkey_rqst_packet(node, user);
	if (packet == NULL) {
		fprintf(stderr, "failed to create packet\n");
		return;
	}

	sign_client_packet(packet, user);
	ret = send_packet_over_socket(user->ssl, user->connfd, packet);
	if (ret < 1)	{
		fprintf(stderr, "failed to send private message\n");
	}
}

/* prints a custom error message*/
void print_error(char *s) {
	const char e[] = "error: ";

	if (s == NULL)
		return;

	write(1, e, strlen(e));
	write(1, s, strlen(s));
	write(1, "\n", 1);
}

/* these functions deal with input from the server. This includes storing
data obtained from the server if necessary and printing messages */

/* takes as input client side meta data and the parsed input from the server
socket and acts on the information accordingly */
void handle_server_input(server_parsed_t *p, user_t *u, request_t *r) {
	if (!is_server_parsed_legal(p) || u == NULL || r == NULL)
		return;

	switch (p->id) {
    case S_MSG_PUBMSG:
			handle_server_pubmsg(p, u);
      break;
    case S_MSG_PRIVMSG:
			handle_server_privmsg(p, u);
      break;
    case S_MSG_USERS:
			handle_server_users(p, u);
      break;
    case S_MSG_GENERIC_ERR:
			print_error(p->error_message);
			/* if an error is returned from a login request, it must be reset */
			if (r->is_request_active) {
				r->is_request_active = false;
				memset(r->username, '\0', USERNAME_MAX+1);
				memset(r->masterkey, '\0', MASTER_KEY_LEN+1);
			}
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
		case S_META_PUBKEY_RESPONSE:
			handle_server_pubkey_response(p, u);
      break;
    default:
      break;
  }

}

/* this functions deals with the list of users sent from the server in response to
a successful /users command */
void handle_server_users(server_parsed_t *p, user_t *u) {
	char *token, *tmp;

	if (!is_server_parsed_legal(p) || u == NULL)
		return;

	tmp = p->users;
	token = strtok(tmp, " ");

	while (token != NULL) {
		write(1, token, strlen(token));
		write(1, "\n", 1);
		token = strtok(NULL, " ");
	}
}

/* verifies that the author of a public message matches the provided public key
from the certificate and if it does prints the message to the interface */
void handle_server_pubmsg(server_parsed_t *p, user_t *u) {
	if (u == NULL)
		return;
	/* verify the signature of the original payload */
	if (!verify_client_payload(p->messages.cert, p->messages.certlen, p->messages.sender,
			p->messages.sig, p->messages.siglen, p->messages.hashed_payload)) {
		fprintf(stderr, "author of message doesn't match\n");
		return;
	}

	write(STDOUT_FILENO, p->messages.message, p->messages.msglen);
	write(STDOUT_FILENO, "\n", 1);
}

/* handles a server response to a previous certificate request. This function decrypts the message
associated with the request, reencrypts it for both itself and the recipient, and sends the message
back to the server. That step is done in the gen_c_privmsg_packet() function */
void handle_server_pubkey_response(server_parsed_t *p, user_t *u) {
	bool verified;
	int ret;
	packet_t *packet = NULL;

	/* verify the information received from the server that was sent from the client was not changed */
	if (!verify_client_payload(u->rsa_keys->cert, u->rsa_keys->certlen, u->username,
			p->pubkey_response.sig,	p->pubkey_response.siglen, p->pubkey_response.hashed_payload)) {
		fprintf(stderr, "authors of packet don't match\n");
	}

	verified = verify_x509_certificate(p->pubkey_response.cert, p->pubkey_response.certlen, p->pubkey_response.username);
	if (!verified) {
		fprintf(stderr, "failed to get recipients certificate\n");
	}

	/* the encryption of the message is done in this function and the ones it calls */
	packet = gen_c_privmsg_packet(p, u);
	if (packet == NULL) {
		fprintf(stderr, "failed to create packet\n");
		return;
	}


	sign_client_packet(packet, u);
	ret = send_packet_over_socket(u->ssl, u->connfd, packet);
	if (ret < 1)	{
		fprintf(stderr, "failed to send user /users packet\n");
	}
}

/* this messages handles a private message from the server. It decrypts the symmetric key
that (should) belong to it and uses it to decrypt the message with AES-128-CBC and the
initialization vector provided */
void handle_server_privmsg(server_parsed_t *p, user_t *u) {
	unsigned char decrypted_key[500], *encrypted_key;
	char decrypted_msg[MAX_PACKET_SIZE] = "";
	int decrypted_msglen, decrypted_keylen;
	unsigned int encrypted_keylen;

	/* verify the signature of the original payload */
	if (!verify_client_payload(p->messages.cert, p->messages.certlen, p->messages.sender,
			p->messages.sig, p->messages.siglen, p->messages.hashed_payload)) {
		fprintf(stderr, "author of message doesn't match\n");
		return;
	}

	/* check if logged in user is the recipient of the message. If they are, use the recipients
	symmetric key, otherwise use the senders */
	if(strncmp(u->username, p->messages.recipient, USERNAME_MAX) == 0) {
		encrypted_keylen = p->messages.r_symkeylen;
		encrypted_key = p->messages.r_symkey;
	}
	else {
		encrypted_keylen = p->messages.s_symkeylen;
		encrypted_key = p->messages.s_symkey;
	}

	/* use the private key to decrypt the selected encrypted symmetric key */
	decrypted_keylen = apply_rsa_decrypt(u->rsa_keys->privkey, u->rsa_keys->privlen, encrypted_keylen,
																			encrypted_key, decrypted_key);
	if (decrypted_keylen < 0) {
		fprintf(stderr, "failed to decrypt key\n");
		return;
	}
	decrypted_key[decrypted_keylen] = '\0';

	/* decrypt the encrypted message using the IV and the now decrypted symmetric key */
	decrypted_msglen = apply_aes( (unsigned char *) decrypted_msg, p->messages.message, p->messages.msglen,
															 decrypted_key, p->messages.iv, DECRYPT);
	if (decrypted_msglen < 0) {
		fprintf(stderr, "failed to decrypt private message\n");
		return;
	}
	decrypted_msg[decrypted_msglen] = '\0';

	/* writes the message to stout */
	write(STDOUT_FILENO, decrypted_msg, decrypted_msglen);
	write(STDOUT_FILENO, "\n", 1);
}

/* this function handles packets sent from the server on register or login
success. In both these instances the same data is returned, so this function is used for both.
This function checks for any errors, and if there are none sets the client to logged
in and sets all the necessary variables */
void handle_server_log_pass(server_parsed_t *p, user_t *u, request_t *r) {
	int decrypt_sz, encrypt_sz;
	unsigned char decrypted_keys[CHUNK], *encrypted_keys, *iv,
	*masterkey;
	keypair_t *keys = NULL;

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
	if (keys == NULL) {
		fprintf(stderr, "failed to obtain user keys\n");
		return;
	}

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
	memset(r->username, '\0', USERNAME_MAX+1);
	memset(r->masterkey, '\0', MASTER_KEY_LEN+1);

	print_error(p->error_message);
}

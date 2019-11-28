#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

/* maximum size for rsa signature*/
#define MAX_SIG_SZ 256

/* definitions for creation of client master key*/
#define MASTER_KEY_LEN 16
#define ITERATION 10000

/* size of the init vector passed to the AES algorithm*/
#define IV_SIZE 16

/* size of the salt used for hashing passwords from clients */
#define SALT_SIZE 32

#define ENCRYPT 1
#define DECRYPT 0

#include <stdbool.h>
#include <openssl/sha.h>

/* defines the common name for the server. this is checked in client.c
when an ssl connection is established*/
#define SERVER_COMMON_NAME "server.example.com"

typedef struct rsa_keypairs {
  unsigned int privlen;
  unsigned int publen;
  char *privkey;
  char *pubkey;
} keypair_t;

unsigned char *create_rand_salt(unsigned int size);
//unsigned char *hash_password(char *input, int size, unsigned char *salt, int salt_size);
unsigned char *hash_password(char *input, unsigned int size, unsigned char *salt, unsigned int salt_size);
unsigned char *gen_master_key(char *username, char *password);

keypair_t *create_rsa_pair(void);
bool is_keypair_legal(keypair_t *k);
void free_keypair(keypair_t *k);

int apply_aes(unsigned char *output, unsigned char *input, int size, unsigned char *key, unsigned char *iv, int enc);

#endif

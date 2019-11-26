#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#define MAX_SIG_SZ 256
/* definitions for creation of client master key*/
#define MASTER_KEY_LEN 64
#define ITERATION 10000

#include <stdbool.h>
#include <openssl/sha.h>

/* defines the common name for the server. this is checked in client.c
when an ssl connection is established*/
#define SERVER_COMMON_NAME "server.example.com"

typedef struct rsa_key_pairs {
  int privlen;
  int publen;
  char *privkey;
  char *pubkey;
} key_pair_t;

unsigned char *create_rand_salt(int size);
unsigned char *hash_password(char *input, int size, unsigned char *salt, int salt_size);
unsigned char *gen_master_key(char *username, char *password);

key_pair_t *create_rsa_pair(void);
void free_key_pair(key_pair_t *k);

#endif

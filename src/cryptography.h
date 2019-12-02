#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "parse_user_input.h"

/* definitions for creation of client master key*/
#define MASTER_KEY_LEN 16
#define ITERATION 10000

/* size of the init vector passed to the AES algorithm*/
#define IV_SIZE 16

/* size of a symmetric key for private message encryption */
#define SYMKEY_SIZE 16

/* size of the salt used for hashing passwords from clients */
#define SALT_SIZE 32

#define ENCRYPT 1
#define DECRYPT 0

/* defines the common name for the server. this is checked in client.c
when an ssl connection is established*/
#define SERVER_COMMON_NAME "server.example.com"

/* struct to hold a rsa key pair in memory */
typedef struct rsa_keypairs {
  unsigned int privlen;
  unsigned int publen;
  unsigned int certlen;
  char *privkey;
  char *pubkey;
  char *cert;
} keypair_t;

/* functions to create random bytes, hash input and create the master key */
unsigned char *create_rand_salt(unsigned int size);
unsigned char *hash_password(char *input, unsigned int size, unsigned char *salt, unsigned int salt_size);
unsigned char *hash_input(char *input, unsigned int size);
unsigned char *gen_master_key(char *username, char *password);
/* functions for the keypair_t struct */
keypair_t *create_rsa_pair(void);
bool is_keypair_legal(keypair_t *k);
void free_keypair(keypair_t *k);
/* functions for creating/using an X509 certificate */
char *gen_hex_of_username_hash(char *username);
int execute_ttp_script(char *username);
char *gen_x509_certificate(char *username, unsigned int *outlen);
X509 *get_x509_from_array(char *cert, unsigned int certlen);
char *obtain_pubkey_from_x509(char *cert, unsigned int certlen, unsigned int *publen);
bool verify_x509_certificate(char *cert, unsigned int certlen, char *username);

/* function to apply AES-128-CBC to an input with the provided salt and initialization vector */
int apply_aes(unsigned char *output, unsigned char *input, int size,
              unsigned char *key, unsigned char *iv, int enc);
/* functions for signature creation and verification */
unsigned int rsa_sign_sha256(EVP_PKEY *key, unsigned char *output, unsigned char* input, unsigned int inlen);
bool rsa_verify_sha256(EVP_PKEY *key, unsigned char *s, unsigned char *i, unsigned int slen, unsigned int ilen);
/* functions for RSA encryption and decryption */
int apply_rsa_encrypt(char *pkey, unsigned int plen, unsigned int inlen, unsigned char *in, unsigned char *out);
int apply_rsa_decrypt(char *pkey, unsigned int plen, unsigned int inlen, unsigned char *in, unsigned char *out);

#endif

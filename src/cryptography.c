#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "safe_wrappers.h"
#include "cryptography.h"
#include "parser.h"

/* creates and returns a salt based on the size given*/
unsigned char *create_rand_salt(int size) {
  unsigned char *salt;

  salt = (unsigned char *) safe_malloc(sizeof(unsigned char) * size);
  if (RAND_priv_bytes(salt, size) < 1) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Failed to create salt\n");
    return NULL;
  }
  return salt;
}

/* returns a hash of the password. If the hash should contain a salt,
the input and salt are concatenated. Otherwise no salt is added */
unsigned char *hash_password(char *input, int size, unsigned char *salt, int salt_size) {
  SHA256_CTX context;
  unsigned char *md, *tmp;
  int length;

  if (input == NULL) return NULL;
  md = (unsigned char *) safe_malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH);
  length = size;

  if (salt != NULL) {
    tmp = (unsigned char *) safe_malloc(sizeof(unsigned char) * size+salt_size);
    memcpy(tmp, input, size);
    memcpy(tmp+size, salt, salt_size);
    length = size+salt_size;
  }
  else {
    tmp = (unsigned char *) safe_malloc(sizeof(unsigned char) * size);
    memcpy(tmp, input, size);
  }

  if (SHA256_Init(&context) < 1) ERR_print_errors_fp(stderr);
  if (SHA256_Update(&context, tmp, length) < 1) ERR_print_errors_fp(stderr);
  if (SHA256_Final(md, &context) < 1) ERR_print_errors_fp(stderr);

  free(tmp);
  return md;
}

/* generates a master key based on a users username and password. this key
is used to encrypt the private key when it is sent to be stored on the server.
uses username as a salt and adds iteration to reduce effectiveness of brute forcing*/
unsigned char *gen_master_key(char *username, char *password) {
  int ret, passlen, saltlen;
  unsigned char *key, *salt;

  if (username == NULL || password == NULL)
    return NULL;

  if ((passlen = strlen(password)) > PASSWORD_MAX)
    return NULL;
  if ((saltlen = strlen(username)) > USERNAME_MAX)
    return NULL;

  key = (unsigned char *) safe_malloc(sizeof(unsigned char) * MASTER_KEY_LEN+1);
  salt = (unsigned char *) safe_malloc(sizeof(unsigned char) * saltlen);
  if (key == NULL || salt == NULL) {
    free(key);
    free(salt);
    return NULL;
  }
  memcpy(salt, username, saltlen);

  ret = PKCS5_PBKDF2_HMAC(password, passlen,
                          salt, saltlen, ITERATION,
                          EVP_sha256(), MASTER_KEY_LEN,
                          key);
  if (ret != 1) {
    free(key);
    free(salt);
    return NULL;
  }

  free(salt);
  key[MASTER_KEY_LEN] = '\0';
  return key;
}

key_pair_t *create_rsa_pair() {
  int ret, keylen = 0;
  bool error = false;
  const int bits = 2048, exponent = 65537;
  BIGNUM *bignum = NULL;
  BIO *biopriv = NULL, *biopub = NULL;
  RSA *rsa = NULL;
  key_pair_t *keys = NULL;

  keys = (key_pair_t *) safe_malloc(sizeof(key_pair_t));
  if (keys == NULL) {
    error = true;
    goto cleanup;
  }
  keys->privkey = NULL;
  keys->pubkey = NULL;

  bignum = BN_new();
  ret = BN_set_word(bignum, exponent);
  if (ret != 1) {
    error = true;
    goto cleanup;
  }

  rsa = RSA_new();
  ret = RSA_generate_key_ex(rsa, bits, bignum, NULL);
  if (ret != 1) {
    error = true;
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  biopriv = BIO_new(BIO_s_mem());
  if (biopriv == NULL) {
    error = true;
    goto cleanup;
  }
  ret = PEM_write_bio_RSAPrivateKey(biopriv, rsa, NULL,
                                    NULL, 0, NULL, NULL);
  if (ret != 1) {
    error = true;
    goto cleanup;
  }

  keylen = BIO_pending(biopriv);
  keys->privkey = (char *) safe_malloc(sizeof(char) * (keylen+1));
  if (keys->privkey == NULL) {
    error = true;
    goto cleanup;
  }
  BIO_read(biopriv, keys->privkey, keylen);
  keys->privkey[keylen] = '\0';
  keys->privlen = keylen;
  BIO_flush(biopriv);

  biopub = BIO_new(BIO_s_mem());
  if (biopub == NULL) {
    error = true;
    goto cleanup;
  }
  ret = PEM_write_bio_RSAPublicKey(biopub, rsa);
  if (ret != 1) {
    error = true;
    goto cleanup;
  }

  keylen = BIO_pending(biopub);
  keys->pubkey = (char *) safe_malloc(sizeof(char) * (keylen+1));
  if (keys->pubkey == NULL) {
    error = true;
    goto cleanup;
  }
  BIO_read(biopub, keys->pubkey, keylen);
  keys->pubkey[keylen] = '\0';
  keys->publen = keylen;
  BIO_flush(biopub);

  printf("privkey: %s\n", keys->privkey);
  printf("pubkey: %s\n", keys->pubkey);

  cleanup:
  
  BIO_free_all(biopub);
  BIO_free_all(biopriv);
  BN_free(bignum);
  RSA_free(rsa);
  if (error) {
    fprintf(stderr, "failed to create rsa pair\n");
    free_key_pair(keys);
  }

  return error ? NULL : keys;
}

void free_key_pair(key_pair_t *k) {
  if (k == NULL)
    return;

  free(k->privkey);
  free(k->pubkey);
  free(k);
}

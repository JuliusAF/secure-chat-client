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

/* creates and returns a salt based on the size given*/
unsigned char *create_rand_salt(unsigned int size) {
  unsigned char *salt;

  salt = safe_malloc(sizeof(unsigned char) * size);
  if (salt == NULL)
    return NULL;

  if (RAND_bytes(salt, size) < 1) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  return salt;
}

/* returns a hash of the input. If the hash should contain a salt,
the input and salt are concatenated. Otherwise no salt is added */
unsigned char *hash_password(char *input, unsigned int size, unsigned char *salt, unsigned int salt_size) {
  SHA256_CTX context;
  unsigned char *md, *tmp;

  if (input == NULL)
    return NULL;

  md = safe_malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH);
  if (md == NULL)
    return NULL;
  tmp = (unsigned char *) input;


  if (SHA256_Init(&context) < 1) {
    fprintf(stderr, "sha init failed\n");
    ERR_print_errors_fp(stderr);
  }

  if (salt != NULL && salt_size != 0) {
    if (SHA256_Update(&context, salt, salt_size) < 1) {
      fprintf(stderr, "sha update failed\n");
      ERR_print_errors_fp(stderr);
    }
  }
  if (SHA256_Update(&context, tmp, size) < 1) {
    fprintf(stderr, "sha update failed\n");
    ERR_print_errors_fp(stderr);
  }
  if (SHA256_Final(md, &context) < 1) {
    fprintf(stderr, "sha final failed\n");
    ERR_print_errors_fp(stderr);
  }

  return md;
}

/* wrapper function to hash things other than passwords. These never add a salt
so the field need not be entered */

unsigned char *hash_input(char *input, unsigned int size) {
  return hash_password(input, size, NULL, 0);
}

/* generates a master key based on a users username and password. this key
is used to encrypt the private key when it is sent to be stored on the server.
uses username as a salt and adds iteration to reduce effectiveness of brute forcing*/
unsigned char *gen_master_key(char *username, char *password) {
  int ret, passlen, saltlen;
  unsigned char *key = NULL, *salt = NULL;

  if (username == NULL || password == NULL)
    return NULL;

  if ((passlen = strlen(password)) > PASSWORD_MAX ||
      (saltlen = strlen(username)) > USERNAME_MAX)
    return NULL;

  key = safe_malloc(sizeof(unsigned char) * MASTER_KEY_LEN+1);
  salt = safe_malloc(sizeof(unsigned char) * saltlen);
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

/* creates an rsa key pair and stores it in the key pair struct. These keys
are created and will be linked to the user who commenced the register request

the function utilizes an error boolean and the goto jump to check whether an
error has occured, and returns NULL if yes and the rsa key pair struct if not */
keypair_t *create_rsa_pair() {
  int ret, keylen = 0;
  bool error = false;
  const int bits = 2048, exponent = 65537;
  BIGNUM *bignum = NULL;
  BIO *biopriv = NULL, *biopub = NULL;
  RSA *rsa = NULL;
  keypair_t *keys = NULL;

  keys = safe_malloc(sizeof(keypair_t));
  if (keys == NULL) {
    error = true;
    goto cleanup;
  }
  /* initializes the variables so that on failure the struct can still be passed
  to free_keypair() */
  keys->privkey = NULL;
  keys->pubkey = NULL;

  /* sets the BIGNUM * and creates an RSA key pair */
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

  /* reads the private key stored in the RSA struct by opening a memroy BIO and
  places it into a character array in PEM format */
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
  keys->privkey = safe_malloc(sizeof(char) * (keylen+1));
  if (keys->privkey == NULL) {
    error = true;
    goto cleanup;
  }
  /* reads the private key into the character array and null terminates it
  for security */
  BIO_read(biopriv, keys->privkey, keylen);
  keys->privkey[keylen] = '\0';
  keys->privlen = keylen;
  BIO_flush(biopriv);

  /* reads the public key stored in the RSA struct by opening a memroy BIO and
  places it into a character array in PEM format */
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
  keys->pubkey = safe_malloc(sizeof(char) * (keylen+1));
  if (keys->pubkey == NULL) {
    error = true;
    goto cleanup;
  }
  /* reads the public key into the character array and null terminates it
  for security */
  BIO_read(biopub, keys->pubkey, keylen);
  keys->pubkey[keylen] = '\0';
  keys->publen = keylen;
  BIO_flush(biopub);

  cleanup:

  BIO_free_all(biopub);
  BIO_free_all(biopriv);
  BN_free(bignum);
  RSA_free(rsa);
  if (error) {
    fprintf(stderr, "failed to create rsa pair\n");
    free_keypair(keys);
  }

  return error ? NULL : keys;
}

/* helper function to for key pairs that checks whether a given keypair_t
struct is legal (no pointers are NULL) */
bool is_keypair_legal(keypair_t *k) {
  return (k != NULL && k->privkey != NULL && k->pubkey != NULL);
}

/* helper function that frees a given key pair*/
void free_keypair(keypair_t *k) {
  if (k == NULL)
    return;

  free(k->privkey);
  free(k->pubkey);
  free(k);
}

/* applies AES-128-cbc encryption to the given output buffer, based on the given
initialization vector and key. The key and IV are 16 bytes. The function
also takes an 'int enc' argument like the actual openSSL interface. This specifies
whether the function is to encrypt or decrypt, and the macro for either is defined
in cryptography.h
Returns:
size of encrypted/decrypted output on success
-1 on failure */
int apply_aes(unsigned char *out, unsigned char *input, int size, unsigned char *key, unsigned char *iv, int enc) {
  int tmp, outlen, ret = 0;

  if (out == NULL || input == NULL ||
      key == NULL || iv == NULL)
    return -1;

  const EVP_CIPHER *type = EVP_aes_128_cbc();
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  if (EVP_CipherInit(ctx, type, key, iv, enc) < 1)
    return -1;
  if ((ret = EVP_CipherUpdate(ctx, out, &tmp, input, size)) < 1)
    return -1;
  outlen = tmp;
  if (EVP_CipherFinal(ctx, out+tmp, &tmp) < 1)
    return -1;
  outlen += tmp;

  EVP_CIPHER_CTX_free(ctx);
  return outlen;
}

/* signs an input byte array into the output argument using an rsa private key passed as
and EVP_PKEY type. Automatically frees the EVP_PKEY after use.
Returns:
the size of the signature on success
0 otherwise */
unsigned int rsa_sign_sha256(EVP_PKEY *key, unsigned char *output, unsigned char* input, unsigned int inlen) {
  unsigned int siglen = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();

  if (key == NULL || output == NULL || input == NULL)
    goto cleanup;

  if (EVP_SignInit(ctx, EVP_sha256()) != 1) {
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }
  if (EVP_SignUpdate(ctx, input, inlen) != 1) {
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }
  if (EVP_SignFinal(ctx, output, &siglen, key) != 1) {
    ERR_print_errors_fp(stderr);
    siglen = 0;
    goto cleanup;
  }

  cleanup:

  EVP_PKEY_free(key);
  EVP_MD_CTX_free(ctx);
  return siglen;
}

/* verifies a given signature, signed with an RSA private key. The EVP_PKEY is
automatically freed.
Returns:
true on signature verification success
false on failure or error */
bool rsa_verify_sha256(EVP_PKEY *key, unsigned char *s, unsigned char *i, unsigned int slen, unsigned int ilen) {
  int ret = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();

  if (key == NULL || s == NULL || i == NULL)
    goto cleanup;

  if (EVP_VerifyInit(ctx, EVP_sha256()) != 1) {
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }
  if (EVP_VerifyUpdate(ctx, i, ilen) != 1) {
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }
  if ((ret = EVP_VerifyFinal(ctx, s, slen, key)) < 0)
    ERR_print_errors_fp(stderr);

  cleanup:

  EVP_PKEY_free(key);
  EVP_MD_CTX_free(ctx);
  return (ret == 1) ? true : false;
}

/* encrypts a given message with a RSA public key in memory in PEM format */
int apply_rsa_encrypt(char *pkey, unsigned int plen, unsigned int inlen, unsigned char *in, unsigned char *out) {
  int ret = -1;
  RSA *rsa = NULL;
  BIO *bio = NULL;

  bio = BIO_new_mem_buf(pkey, plen);
  if (bio == NULL)
    goto cleanup;

  rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
  if (rsa == NULL)
    goto cleanup;

  ret = RSA_public_encrypt(inlen, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
  if (ret < 0)
    ERR_print_errors_fp(stderr);

  cleanup:

  BIO_free_all(bio);
  RSA_free(rsa);
  return ret;
}

/* decrypts a given rsa encrypted buffer with the provided private key in PEM format */
int apply_rsa_decrypt(char *pkey, unsigned int plen, unsigned int inlen, unsigned char *in, unsigned char *out) {
  int ret = -1;
  RSA *rsa = NULL;
  BIO *bio = NULL;

  bio = BIO_new_mem_buf(pkey, plen);
  if (bio == NULL)
    goto cleanup;

  rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
  if (rsa == NULL)
    goto cleanup;

  ret = RSA_private_decrypt(inlen, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
  if (ret < 0)
    ERR_print_errors_fp(stderr);

  cleanup:

  BIO_free_all(bio);
  RSA_free(rsa);
  return ret;
}

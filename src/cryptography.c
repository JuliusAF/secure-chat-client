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

  salt = safe_malloc(size * sizeof *salt);
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

  md = safe_malloc(SHA256_DIGEST_LENGTH * sizeof *md);
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

  key = safe_malloc(MASTER_KEY_LEN+1 * sizeof *key);
  salt = safe_malloc(saltlen * sizeof *salt);
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

/* creates a rsa private key stores it in the key pair struct. These keys
are created and will be linked to the user who commenced the register request.
It writes this private key to the file specified in keypath, used to create a
CA signed certificate and a public key 

the function utilizes an error boolean and the goto jump to check whether an
error has occured, and returns NULL if yes and the rsa key pair struct if not */
keypair_t *create_rsa_pair() {
  const char keypath[] = "clientkeys/key.pem";
  int ret, keylen = 0;
  bool error = false;
  const int bits = 2048, exponent = 65537;
  BIGNUM *bignum = NULL;
  BIO *biopriv = NULL;
  RSA *rsa = NULL;
  keypair_t *keys = NULL;
  FILE *keyfile = NULL;

  keys = safe_malloc(sizeof *keys);
  if (keys == NULL) {
    error = true;
    goto cleanup;
  }
  /* initializes the variables so that on failure the struct can still be passed
  to free_keypair() */
  keys->privkey = NULL;
  keys->pubkey = NULL;
  keys->cert = NULL;

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

  /* writes the private key to file */
  keyfile = fopen(keypath, "w+");
  if (keyfile == NULL) {
    error = true;
    goto cleanup;
  }
  ret = PEM_write_RSAPrivateKey(keyfile, rsa, NULL, NULL, 0, NULL, NULL);
  fclose(keyfile);
  if (ret < 1) {
    error = true;
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
  keys->privkey = safe_malloc(keylen+1 * sizeof *keys->privkey);
  if (keys->privkey == NULL) {
    error = true;
    goto cleanup;
  }
  /* reads the private key into the character array and null terminates it */
  BIO_read(biopriv, keys->privkey, keylen);
  keys->privkey[keylen] = '\0';
  keys->privlen = keylen;
  BIO_flush(biopriv);

  cleanup:

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
  return (k != NULL && k->privkey != NULL && k->pubkey != NULL && k->cert != NULL);
}

/* helper function that frees a given key pair*/
void free_keypair(keypair_t *k) {
  if (k == NULL)
    return;

  free(k->cert);
  free(k->privkey);
  free(k->pubkey);
  free(k);
}

/* creates a hexadecimal string of a hash of a username. used to create a unique
common name for a X509 certificate */
char *gen_hex_of_username_hash(char *username) {
  unsigned char *hash = NULL;
  char *hex_hash = NULL, tmp[USERNAME_MAX+1] = "";

  memset(tmp, '\0', USERNAME_MAX+1);
  memcpy(tmp, username, USERNAME_MAX);

  hash = hash_input(tmp, strlen(tmp));
  if (hash == NULL)
    return NULL;

  hex_hash = safe_malloc(sizeof(char) * (SHA256_DIGEST_LENGTH*2)+1);
  if (hex_hash == NULL) {
    free(hash);
    return NULL;
  }

  for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    sprintf(&hex_hash[i*2], "%02X", hash[i]);
  hex_hash[SHA256_DIGEST_LENGTH*2] = '\0';

  free(hash);
  return hex_hash;
}

/* the function calls the trusted third party to create a certificate of the
key.pem file in the clientkeys/ directory */
int execute_ttp_script(char *username) {
  int ret = -1;
  char exec_script[200] = "./trustedthirdparty.sh ";
  char ignore_output[100] = " >/dev/null 2>&1";
  char *hashed_username = NULL;

  if (username == NULL)
    goto cleanup;

  hashed_username = gen_hex_of_username_hash(username);
  if (hashed_username == NULL)
    goto cleanup;

  strncat(exec_script, hashed_username, SHA256_DIGEST_LENGTH*2);
  strncat(exec_script, ignore_output, strlen(ignore_output));

  if (system("chmod 755 trustedthirdparty.sh") < 0)
    goto cleanup;
  if (system(exec_script) < 0)
    goto cleanup;
  ret = 1;
  cleanup:

  free(hashed_username);
  return ret;
}

/* this function reads a certificate from disk, writes it to memory and returns it as a character
array, the size is stored in outlen */
char *gen_x509_certificate(char *username, unsigned int *outlen) {
  int ret;
  const char certpath[] = "clientkeys/cert.pem";
  char *certificate = NULL;
  X509 *cert = NULL;
  BIO *bio = NULL;
  FILE *keyfile = NULL;

  if (username == NULL)
    return NULL;

  ret = execute_ttp_script(username);
  if (ret < 1)
    goto cleanup;

  keyfile = fopen(certpath, "r");
  if (keyfile == NULL)
    goto cleanup;

  cert = PEM_read_X509(keyfile, NULL, NULL, NULL);
  fclose(keyfile);
  if (cert == NULL)
    goto cleanup;

  bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    goto cleanup;

  ret = PEM_write_bio_X509(bio, cert);
  if (ret < 1)
    goto cleanup;

  *outlen = BIO_pending(bio);

  certificate = safe_malloc(sizeof(char) * (*outlen+1));
  if (certificate == NULL)
    goto cleanup;

  BIO_read(bio, certificate, *outlen);
  certificate[*outlen] = '\0';
  cleanup:

  BIO_free_all(bio);
  X509_free(cert);
  return certificate;
}

/* returns a X509 certificate from a certificate stored in memory */
X509 *get_x509_from_array(char *cert, unsigned int certlen) {
  X509 *certificate = NULL;
  BIO *bio = NULL;

  bio = BIO_new_mem_buf(cert, certlen);
  if (bio == NULL)
    goto cleanup;

  certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if (certificate == NULL)
    goto cleanup;

  cleanup:

  BIO_free_all(bio);
  return certificate;
}

/* gets the public key associated with an X509 certificate, PEM encoded in a char array */
char *obtain_pubkey_from_x509(char *cert, unsigned int certlen, unsigned int *publen) {
  int ret;
  char *pubkey = NULL;
  X509 *certificate = NULL;
  EVP_PKEY *key = NULL;
  BIO *bio = NULL;

  if (cert == NULL)
    return NULL;

  certificate = get_x509_from_array(cert, certlen);

  key = X509_get0_pubkey(certificate);
  if (key == NULL)
    goto cleanup;

  bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    goto cleanup;

  ret = PEM_write_bio_PUBKEY(bio, key);
  if (ret < 1)
    goto cleanup;

  *publen = BIO_pending(bio);
  pubkey = safe_malloc(sizeof(char) * *publen+1);
  if (pubkey == NULL)
    goto cleanup;

  BIO_read(bio, pubkey, *publen);
  pubkey[*publen] = '\0';

  cleanup:

  X509_free(certificate);
  BIO_free_all(bio);
  return pubkey;
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

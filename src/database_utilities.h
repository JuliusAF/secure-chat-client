#ifndef DATABASE_UTILITIES_H
#define DATABASE_UTILITIES_H

#include <stdbool.h>
#include <sqlite3.h>
#include "cryptography.h"

#define PUB_MSG_TYPE 1
#define PRIV_MSG_TYPE 2

/* holds the user information fetched from the database on a successful login or register */
typedef struct fetched_user_info {
  unsigned char iv[IV_SIZE+1];
  unsigned int encrypt_sz;
  unsigned char *encrypted_keys;
} fetched_userinfo_t;

/* this struct holds the information stored in the database for messages */
typedef struct messages_components {
  /* every message has these variables */
  int type;
  unsigned int msglen;
  unsigned char *message;
  unsigned int publen;
  char *pubkey;
  unsigned int siglen;
  unsigned char *sig;
  /* only a private message has these variables */
  unsigned int reclen;
  char* recipient;
  unsigned char *iv;
  unsigned int s_symkeylen;
  unsigned char *s_symkey;
  unsigned int r_symkeylen;
  unsigned char *r_symkey;
} msg_components_t;

/* a queue of message component structs, created and modified when messages a fetched
from the database. This is returned on success for private and public messages and holds,
in chronological order, the messages fetched from thr database. */
typedef struct msg_qeue {
  unsigned int size;
  unsigned int top;
  /* stores the rowid of the last message added */
  signed long long max_rowid;
  msg_components_t **messages;
} msg_queue_t;

/* functions for the user info struct */
bool is_fetched_userinfo_legal(fetched_userinfo_t *f);
void free_fetched_userinfo(fetched_userinfo_t *f);

/* functions for msg_components_t */
msg_components_t *assign_msg_components(sqlite3_stmt *res);
void initialize_msg_components(msg_components_t *m);
void free_msg_components(msg_components_t *m);

/* functions for msg_queue_t */
msg_queue_t *initialize_msg_queue(void);
int add_msg_component(msg_queue_t *q, msg_components_t *m);
void free_msg_queue(msg_queue_t *q);

#endif

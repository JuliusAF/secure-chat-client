#ifndef DATABASE_UTILITIES_H
#define DATABASE_UTILITIES_H

#include <stdbool.h>
#include <sqlite3.h>

#define PUB_MSG_TYPE 1
#define PRIV_MSG_TYPE 2

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

typedef struct msg_qeue {
  unsigned int size;
  unsigned int top;
  signed long long max_rowid;
  msg_components_t **messages;
} msg_queue_t;

/* functions for msg_components_t */
msg_components_t *assign_msg_components(sqlite3_stmt *res);
void initialize_msg_components(msg_components_t *m);
void free_msg_components(msg_components_t *m);

/* functions for msg_queue_t */
msg_queue_t *initialize_msg_queue(void);
int add_msg_component(msg_queue_t *q, msg_components_t *m);
void free_msg_queue(msg_queue_t *q);

#endif

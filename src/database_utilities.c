#include <stdlib.h>
#include "database_utilities.h"
#include "cryptography.h"
#include "safe_wrappers.h"

/* creates and returns a msg_components_t struct that contains all relevant
information stored in the sqlite3 res object. The variables accessed and stored
are dependent on what type of message it is. Private messages require more
information than */
msg_components_t *assign_msg_components(sqlite3_stmt *res) {
  const unsigned char *tmp;
  msg_components_t *m;

  if (res == NULL)
    return NULL;

  m = safe_malloc(sizeof(msg_components_t));
  if (m == NULL)
    return NULL;

  initialize_msg_components(m);

  /* A row in the database for MESSAGES either has all fields filled for private
  messages or only some of them for public messages. This checks if the first
  column that can be NULL, recipients, is NULL. If it is, the message type is
  a public message */
  if (sqlite3_column_type(res, 4) == SQLITE_NULL){
    m->type = PUB_MSG_TYPE;
  }
  else
    m->type = PRIV_MSG_TYPE;


  /* find lengths of the character arrays for all messages */
  m->msglen = sqlite3_column_bytes(res, 1);
  m->publen = sqlite3_column_bytes(res, 2);
  m->siglen = sqlite3_column_bytes(res, 3);

  m->message = safe_malloc(sizeof(unsigned char) * m->msglen+1);
  m->pubkey = safe_malloc(sizeof(char) * m->publen+1);
  m->sig = safe_malloc(sizeof(unsigned char) * m->siglen+1);
  if (m->message == NULL || m->pubkey == NULL || m->sig == NULL) {
    free_msg_components(m);
    return NULL;
  }

  /* copy the components that are always in a msg_components_t struct into their
  respective fields */
  tmp = sqlite3_column_blob(res, 1);
  memcpy(m->message, tmp, m->msglen);
  m->message[m->msglen] = '\0';

  tmp = sqlite3_column_blob(res, 2);
  memcpy(m->pubkey, tmp, m->publen);
  m->pubkey[m->publen] = '\0';

  tmp = sqlite3_column_blob(res, 3);
  memcpy(m->sig, tmp, m->siglen);
  m->sig[m->siglen] = '\0';

  /* if the message is private, add the components needs for a private message */
  if (m->type == PRIV_MSG_TYPE) {
    /* find the lengths of the extra componenets needed for private messages */
    m->reclen = sqlite3_column_bytes(res, 4);
    if (m->reclen > USERNAME_MAX) {
      free_msg_components(m);
      return NULL;
    }
    m->s_symkeylen = sqlite3_column_bytes(res, 6);
    m->r_symkeylen = sqlite3_column_bytes(res, 7);

    m->recipient = safe_malloc(sizeof(char) * m->reclen+1);
    /* IV size is constant, defined in IV_SIZE */
    m->iv = safe_malloc(sizeof(unsigned char) * IV_SIZE+1);
    m->s_symkey = safe_malloc(sizeof(unsigned char) * m->s_symkeylen+1);
    m->r_symkey = safe_malloc(sizeof(unsigned char) * m->r_symkeylen+1);
    if (m->recipient == NULL || m->s_symkey == NULL || m->r_symkey == NULL || m->iv == NULL) {
      free_msg_components(m);
      return NULL;
    }

    /* copy the private message components into their respective fields */
    tmp = sqlite3_column_text(res, 4);
    memcpy(m->recipient, tmp, m->reclen);
    m->recipient[m->reclen] = '\0';

    if (sqlite3_column_bytes(res, 5) != IV_SIZE) {
      free_msg_components(m);
      return NULL;
    }
    tmp = sqlite3_column_blob(res, 5);
    memcpy(m->iv, tmp, IV_SIZE);
    m->iv[IV_SIZE] = '\0';

    tmp = sqlite3_column_blob(res, 6);
    memcpy(m->s_symkey, tmp, m->s_symkeylen);
    m->s_symkey[m->s_symkeylen] = '\0';

    tmp = sqlite3_column_blob(res, 7);
    memcpy(m->r_symkey, tmp, m->r_symkeylen);
    m->r_symkey[m->r_symkeylen] = '\0';
  }

  return m;
}

/* sets all sizes to 0, sets the type to 0, and sets all pointers to NULL*/
void initialize_msg_components(msg_components_t *m) {
  if (m == NULL)
    return;

  m->type = 0;
  m->msglen = 0;
  m->message = NULL;
  m->publen = 0;
  m->pubkey = NULL;
  m->siglen = 0;
  m->sig = NULL;
  m->reclen = 0;
  m->recipient = NULL;
  m->iv = NULL;
  m->s_symkeylen = 0;
  m->s_symkey = NULL;
  m->r_symkeylen = 0;
  m->r_symkey = NULL;

}

/* free a msg_components_t struct. Every pointer in the struct is initialized
to NULL when its created, meaning even if the type is no that of a private message,
free can still be called on the pointer */
void free_msg_components(msg_components_t *m) {
  if (m == NULL)
    return;

  free(m->message);
  free(m->pubkey);
  free(m->sig);
  free(m->recipient);
  free(m->iv);
  free(m->s_symkey);
  free(m->r_symkey);
  free(m);
}

/* creates, initializes and returns a message queue used to store the variable
amount of messages pulled from the databse */
msg_queue_t *initialize_msg_queue(void) {
  const int size = 40;
  msg_queue_t *queue = safe_malloc(sizeof(msg_queue_t));
  if (queue == NULL)
    return NULL;

  queue->messages = safe_malloc(sizeof(msg_components_t *) * size);
  queue->size = size;
  queue->top = 0;
  queue->max_rowid = 0;

  return queue;
}

/* adds a msg_components_t struct to the queue. I call it a queue but
the operation is more reminiscent of pushing to a stack. The data structure
if FIFO though. */
int add_msg_component(msg_queue_t *q, msg_components_t *m) {
  msg_components_t **tmp;
  const int inc = 40;

  if (q == NULL || m == NULL)
    return -1;

  if (q->top == q->size-1) {
    tmp = realloc(q->messages, sizeof(msg_components_t *) * (q->size+inc));
    if (tmp == NULL) {
      free_msg_components(m);
      free_msg_queue(q);
      return -1;
    }
    q->messages = tmp;
    q->size += inc;
  }

  q->messages[q->top] = m;
  q->top++;

  return 1;
}

/* clears every msg_components_t struct stored in the queue */
void free_msg_queue(msg_queue_t *q) {
  if (q == NULL)
    return;

  for (unsigned int i = 0; i < q->top; i++)
    free_msg_components(q->messages[i]);

  free(q->messages);
  free(q);
}

#include <stdlib.h>
#include "database_utilities.h"
#include "cryptography.h"
#include "safe_wrappers.h"

/* checks whether a fetched_userinfo_t struct is valid i.e has all pointers
not NULL*/
bool is_fetched_userinfo_legal(fetched_userinfo_t *f) {
  return (f != NULL && f->encrypted_keys != NULL);
}

/* frees a given fetched_userinfo_t struct*/
void free_fetched_userinfo(fetched_userinfo_t *f) {
  if (f == NULL)
    return;

  free(f->encrypted_keys);
  free(f);
}

/* creates and returns a msg_components_t struct that contains all relevant
information stored in the sqlite3 res object. The variables accessed and stored
are dependent on what type of message it is. Private messages require more
information than public messages */
msg_components_t *assign_msg_components(sqlite3_stmt *res) {
  const unsigned char *tmp;
  msg_components_t *m;

  if (res == NULL)
    return NULL;

  m = safe_malloc(sizeof *m);
  if (m == NULL)
    return NULL;

  initialize_msg_components(m);

  /* A row in the database for MESSAGES either has all fields filled for private
  messages or only some of them for public messages. This checks if the first
  column that can be NULL, recipients, is NULL. If it is, the message type is
  a public message */
  if (sqlite3_column_type(res, 5) == SQLITE_NULL){
    m->type = PUB_MSG_TYPE;
  }
  else
    m->type = PRIV_MSG_TYPE;


  /* find lengths of the character arrays for all messages */
  m->msglen = sqlite3_column_bytes(res, 1);
  m->certlen = sqlite3_column_bytes(res, 2);
  m->siglen = sqlite3_column_bytes(res, 3);
  /* check that size of username doesnt exceed max */
  if (sqlite3_column_bytes(res, 4) > USERNAME_MAX)
    return NULL;

  m->message = safe_malloc(m->msglen+1 * sizeof *m->message);
  m->cert = safe_malloc(m->certlen+1 * sizeof *m->cert);
  m->sig = safe_malloc(m->siglen+1 * sizeof *m->sig);
  m->sender = safe_malloc(USERNAME_MAX+1 * sizeof *m->sender);
  if (m->message == NULL || m->cert == NULL || m->sig == NULL || m->sender == NULL) {
    free_msg_components(m);
    return NULL;
  }

  /* copy the components that are always in a msg_components_t struct into their
  respective fields */
  tmp = sqlite3_column_blob(res, 1);
  memcpy(m->message, tmp, m->msglen);
  m->message[m->msglen] = '\0';

  tmp = sqlite3_column_blob(res, 2);
  memcpy(m->cert, tmp, m->certlen);
  m->cert[m->certlen] = '\0';

  tmp = sqlite3_column_blob(res, 3);
  memcpy(m->sig, tmp, m->siglen);
  m->sig[m->siglen] = '\0';

  tmp = sqlite3_column_text(res, 4);
  memset(m->sender, '\0', USERNAME_MAX+1);
  memcpy(m->sender, tmp, sqlite3_column_bytes(res, 4));
  
  /* if the message is private, add the components needs for a private message */
  if (m->type == PRIV_MSG_TYPE) {
    /* find the lengths of the extra componenets needed for private messages */
    m->reclen = sqlite3_column_bytes(res, 5);
    if (m->reclen > USERNAME_MAX) {
      free_msg_components(m);
      return NULL;
    }
    m->s_symkeylen = sqlite3_column_bytes(res, 7);
    m->r_symkeylen = sqlite3_column_bytes(res, 8);

    m->recipient = safe_malloc(m->reclen+1 * sizeof *m->recipient);
    /* IV size is constant, defined in IV_SIZE */
    m->iv = safe_malloc(IV_SIZE+1 * sizeof *m->iv);
    m->s_symkey = safe_malloc(m->s_symkeylen+1 * sizeof *m->s_symkey);
    m->r_symkey = safe_malloc(m->r_symkeylen+1 * sizeof *m->r_symkey);
    if (m->recipient == NULL || m->s_symkey == NULL || m->r_symkey == NULL || m->iv == NULL) {
      free_msg_components(m);
      return NULL;
    }

    /* copy the private message components into their respective fields */
    tmp = sqlite3_column_text(res, 5);
    memcpy(m->recipient, tmp, m->reclen);
    m->recipient[m->reclen] = '\0';

    if (sqlite3_column_bytes(res, 6) != IV_SIZE) {
      free_msg_components(m);
      return NULL;
    }
    tmp = sqlite3_column_blob(res, 6);
    memcpy(m->iv, tmp, IV_SIZE);
    m->iv[IV_SIZE] = '\0';

    tmp = sqlite3_column_blob(res, 7);
    memcpy(m->s_symkey, tmp, m->s_symkeylen);
    m->s_symkey[m->s_symkeylen] = '\0';

    tmp = sqlite3_column_blob(res, 8);
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
  m->certlen = 0;
  m->cert = NULL;
  m->siglen = 0;
  m->sig = NULL;
  m->sender = NULL;
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
  free(m->cert);
  free(m->sig);
  free(m->sender);
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
  msg_queue_t *queue = safe_malloc(sizeof *queue);
  if (queue == NULL)
    return NULL;

  queue->messages = safe_malloc(size * sizeof *queue->messages);
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

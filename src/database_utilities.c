#include <stdlib.h>
#include "database_utilities.h"
#include "safe_wrappers.h"

msg_components_t *assign_msg_components(sqlite3_stmt *res);

void initialize_msg_components(msg_components_t *m) {
  if (m == NULL)
    return;

  m->type = 0;
  m->message = NULL;
  m->pubkey = NULL;
  m->sig = NULL;
  m->recipient = NULL;
  m->iv = NULL;
  m->s_symkey = NULL;
  m->r_symkey = NULL;

}

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

msg_queue_t *initialize_msg_queue(void) {
  msg_queue_t *queue = safe_malloc(sizeof(msg_queue_t));
  if (queue == NULL)
    return NULL;

  queue->messages = malloc(sizeof(msg_components_t *) * 30);
  queue->size = 30;
  queue->top = 0;

  return queue;
}

int add_msg_component(msg_queue_t *q, msg_components_t *m) {
  msg_components_t **tmp;
  const int inc = 20;

  if (q == NULL || m == NULL)
    return -1;

  if (q->top == q->size-1) {
    tmp = realloc(q->messages, sizeof(msg_components_t *) * q->size+inc);
    if (tmp == NULL) {
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

void free_msg_queue(msg_queue_t *q) {
  if (q == NULL)
    return;

  for (unsigned int i = 0; i < q->top; i++)
    free_msg_components(q->messages[i]);

  free(q);
}

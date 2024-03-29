#include "safe_wrappers.h"

/* memory allocation functions that have an error check included */

void *safe_malloc(size_t s) {
  void *ptr = malloc(s);
  if (ptr == NULL) {
    perror("failed to allocate memory");
  }
  return ptr;
}

void *safe_strdup(char *s) {
  char *tmp = strdup(s);
  if (tmp == NULL) {
    perror("failed to dup string");
  }
  return tmp;
}

void *safe_realloc(void *ptr, size_t s) {
  void *tmp = realloc(ptr, s);
  if (tmp == NULL) {
    perror("failed to reallocate memory");
    return ptr;
  }
  return tmp;
}

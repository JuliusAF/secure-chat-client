#ifndef SAFE_WRAPPERS_H
#define SAFE_WRAPPERS_H

void *safe_malloc(size_t s);
void *safe_strdup(char *s);
void *safe_realloc(void *ptr, size_t s);

#endif

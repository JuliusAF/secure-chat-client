#ifndef SAFE_WRAPPERS_H
#define SAFE_WRAPPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *safe_malloc(size_t s);
void *safe_strdup(char *s);
void *safe_realloc(void *ptr, size_t s);

#endif

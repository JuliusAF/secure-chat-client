#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"
#include "client_utilities.h"

int read_stdin(char *buffer, int size) {
	int bytes_read = 0, index = 0;
	char c;

	if (buffer == NULL || size == 0) {
		return -1;
	}

	while (read(STDIN_FILENO, &c, 1) == 1 && index < size - 1) {
		bytes_read++;

		if (c == '\n') {
			buffer[index] = '\0';
			return bytes_read;
		}
		buffer[index] = c;
		index++;
	}

	buffer[index] = '\0';
	return bytes_read;
}

void print_parse_error(command_t *n) {
  if(n != NULL && n->command == COMMAND_ERROR)
    printf("error: %s\n", n->error_message);
}

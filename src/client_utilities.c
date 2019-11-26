#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include "safe_wrappers.h"
#include "parser.h"
#include "client_utilities.h"


/* Initializes the struct that holds the information of the user
logged into the current instance of the client application*/
user_t *initialize_user_info() {
	user_t *user = safe_malloc(sizeof(user_t));
	if (user == NULL)
		return NULL;

	user->is_logged = false;
	strcpy(user->username, "");
	memset(user->masterkey, '\0', MASTER_KEY_LEN+1);
	user->rsa_keys = NULL;

	return user;
}

/* function reads input of fixed size from stdin*/
int read_stdin(char *buffer, int size) {
	int bytes_read = 0, index = 0;
	char c;

	if (buffer == NULL || size == 0) {
		return -1;
	}

	while (read(STDIN_FILENO, &c, 1) == 1 && index < size-1) {
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
/* creates a date string from a given time_t struct */
int create_date_string(char *date, time_t t) {
	struct tm *tmp;

	if (t < 0) {
		perror("time(null) failed");
		return -1;
	}
  /* Code taken from example supplied by the linux man page on strftime*/
  tmp = localtime(&t);

  if (tmp == NULL) {
    perror("localtime");
    return -1;
  }
  if (strftime(date, 60, DATE_FORMAT, tmp) == 0) {
    fprintf(stderr, "strftime returned 0");
    return -1;
  }
  return 1;
}

/* Takes as input a buffer, a parsed command and the user info. If the command is a private
or public message, it concatenates the fields for the corresponding message
into one string and stores it in the buffer.*/
int create_formatted_msg(char *dest, command_t *n, user_t *u) {
	char date[60];
	int ret;

	ret = create_date_string(date, time(NULL));
	if (ret < 1 || strlen(date) > 59)
		return -1;

	strcpy(dest, "");
	strcpy(dest, date);
	strncat(dest, " ", 1);
	strncat(dest, u->username, strlen(u->username));
	if(n->command == COMMAND_PRIVMSG) {
    strncat(dest, ": @", 3);
    strncat(dest, n->privmsg.username, strlen(n->privmsg.username));
    strncat(dest, " ", 1);
		strncat(dest, n->privmsg.message, strlen(n->privmsg.message));
  }
  else {
    strncat(dest, ": ", 2);
		strncat(dest, n->message, strlen(n->message));
  }

	return 1;
}

/* this function handles the user input dependent of how it was parsed.
From this function, the packets for each command are created and sent
to the server*/
void handle_user_input(command_t *n, user_t *u) {
	if (n == NULL)
    return;

  switch (n->command) {
    case COMMAND_LOGIN:
			if (u->is_logged) {
				print_error("client already logged in");
				break;
			}
      break;
    case COMMAND_REGISTER:
			if (u->is_logged) {
				print_error("you cannot register a new account while logged in");
				break;
			}
      break;
    case COMMAND_PRIVMSG:
			if (!u->is_logged) {
				print_error("you must be logged in to send a private message");
				break;
			}
      break;
    case COMMAND_PUBMSG:
			if (!u->is_logged) {
				print_error("you must be logged in to send a public message");
				break;
			}
      break;
    case COMMAND_USERS:
			if (!u->is_logged) {
				print_error("user is not currently logged in");
				break;
			}
      break;
    case COMMAND_EXIT:
      break;
		case COMMAND_ERROR:
			print_error(n->error_message);
			break;
    default:
      break;
  }
}

/* prints an error message stored in the parsed input struct*/
void print_parse_error(command_t *n) {
  if(n != NULL && n->command == COMMAND_ERROR)
    printf("error: %s\n", n->error_message);
}

/* prints a custom error message*/
void print_error(char *s) {
	if (s == NULL)
		return;

	printf("error: %s\n", s);
}

/* packets received from the server are dealt with here*/
void handle_server_output(void);

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"

int main( int argc, const char* argv[] )
{
	printf( "\nHello World\n\n" );

  char* input = read_input(STDIN_FILENO);
	command_t *node = parse_input(input);
	if(node == NULL) {
		printf("wtf \n");
		free(node);
		return 0;
	}

	switch(node->command) {
    case COMMAND_ERROR:
      printf("error message: %s \n", node->error_message);
      break;
    case COMMAND_LOGIN:
      printf("login, username: %s \n", node->acc_details.username);
      printf("login, password: %s \n", node->acc_details.password);
      break;
    case COMMAND_REGISTER:
      printf("register, username: %s \n", node->acc_details.username);
      printf("register, password: %s \n", node->acc_details.password);
      break;
    case COMMAND_PUBMSG:
      printf("public message: %s \n", node->message);
      break;
    case COMMAND_PRIVMSG:
      printf("private message: %s \n", node->privmsg.message);
    	printf("private message, username: %s \n", node->privmsg.username);
      break;
		case COMMAND_EXIT:
			printf("exit \n");
			break;
		case COMMAND_USERS:
			printf("users \n");
			break;
    default:
      break;
	  }
	free_node(node);
	free(input);
		//free(node);
  //n = read(STDIN_FILENO, buf, sizeof(buf));
  /*input = trim_front_whitespace(input);
  int size = trim_back_whitespace(input);
	size = strlen(input);
  char* temp, *token;
  const char delim[] = " \n\t\v";
  temp = (char *) malloc(sizeof(char)*strlen(input)+1);
  memcpy(temp, input, strlen(input)+1);

  token = strtok(temp, delim);
  int temp_size = strlen(temp);
  printf("temp size: %d \n", temp_size);
  printf("input size: %d \n", size);
  printf("The input string: %s \n", input);
  printf("The token string: %s \n", token);
	token++;
	temp_size = strlen(token);
	printf("token size: %d \n", temp_size);
	if(strcmp(input, token) != 0)
		input += strlen(token);
	printf("The input2 string: %s \n", input);

	token = strtok(NULL, delim);
	printf("The token2 string: %s \n", token);
  printf("The temp2 string: %s \n", temp);

	if(strcmp(input,"/exit") != 0) {
		printf("oh no \n");
	}*/

	return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"

int main( int argc, const char* argv[] )
{
	printf( "\nHello World\n\n" );

  char* input = read_input(STDIN_FILENO);
  //n = read(STDIN_FILENO, buf, sizeof(buf));
  input = trim_front_whitespace(input);
  int size = trim_back_whitespace(input);
  char* temp, *token;
  const char delim[] = " \n\t\v";
  temp = (char *) malloc(sizeof(input));
  memcpy(temp, input, strlen(input+1));

  token = strtok(temp, delim);
  int temp_size = strlen(temp);
  printf("temp size: %d \n", temp_size);
  printf("input size: %d \n", size);
  printf("The input string: %s \n", input);
  printf("The token string: %s \n", token);
  printf("The temp string: %s \n", temp);

}

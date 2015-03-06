/* Test program for Protocol Construction */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015

   Sources:
   http://c.learncodethehardway.org/book/ex16.html
   For help with creating structs and passing them between programs

   Mr. Stone for help with compiling programs to include devurandom.c functions
   And debugging header files
   Debuggging client decrypt function

   http://cboard.cprogramming.com/c-programming/136163-help-array-def-different-file.html
   For help with using header files to share data

   Alex Mitchell for clarification of assignment

   Ethan Ratcliff for help with using timestamp as a union

   Zhi and Albert for help with creating makefile

   Stone for help with display bytes function

   Organize everything. Consolidate methods. Document.
*/

#include <stdio.h>
#include <assert.h>
#include <crypto_box.h>
#include "client.h"
#include "server.h"

/* display the contents of an array of unsigned char values. */
void display_bytes(const unsigned char *byte_vector, long long int length) {
  long long int counter = 0;
  while (counter < length) {
    (void) printf("%02x", byte_vector[counter]);
    (void) putchar((++counter & 0xF) ? ' ' : '\n');
  }

  if (counter & 0xF)
    putchar('\n');
  putchar('\n');
}


/* function to simulate system moderating secure client and server communication */
int main(){

  /* generate nonce N0 and server keypair and display them */  
  initialCommunicationRequirements();

  /* initial function to establish communication with server */
  clientInitialCommunication();

  /* server response to initial communication */
  serverInitialResponse();

  /* client asks the server a question */
  clientAskQuestion();

  /* server responds to client question */
  serverAnswerQuestion();

  /* client verifies and reads response */
  clientReadAnswer();

  /* communication successful */
  return NO_ERROR;

}

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

To do:
Parse server timestamp on client end. Create a union to save the bytes into and then access it as a time_t value, and print to make sure that the correct time is used. Maybe even print the time in both bytes and regular time before sending. Then figure out how to compare times to be within 90 seconds.

Organize everything. Consolidate methods. Document.
*/

#include <stdio.h>
#include <assert.h>
#include <crypto_box.h>
#include "client.h"
#include "server.h"

/* Display the contents of an array of unsigned char values. */

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


int main(){

  /* Generate and display key pair (Es, Ds) */
  serverGenerateKeyPair();

  /* Generate and display nonce, N0 */  
  generateN0();

  clientInitialCommunication();

  /* Server decrypts nonce sent from client */
  serverInitialResponse();

  clientAskQuestion();

  serverAnswerQuestion();

  clientReadAnswer();

  return NO_ERROR;

}

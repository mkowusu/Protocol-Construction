/* Test program for Protocol Construction */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015

   Sources:
   http://c.learncodethehardway.org/book/ex16.html
   For help with creating structs and passing them between programs

   Mr. Stone for help with compiling programs to include devurandom.c functions
   And debugging header files

   http://cboard.cprogramming.com/c-programming/136163-help-array-def-different-file.html
   For help with using header files to share data

Alex Mitchell for clarification of assignment

Zhi and Albert for help with creating makefile
*/

#include <stdio.h>
#include <assert.h>
#include "crypto_box.h"
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
  int result;
  long long int counter;
  char message[INTERNAL_MESSAGE_LENGTH] = "This is the forest primeval ...\n";

  /* Prepare and display a message for encryption. */

  for (counter = 0; counter < crypto_box_ZEROBYTES; counter++)
    plaintext[counter] = 0;
  for (counter = 0; counter < INTERNAL_MESSAGE_LENGTH; counter++)
    plaintext[crypto_box_ZEROBYTES + counter] = message[counter];

  /* Generate and display nonce, N0 */  
  printf("\nServer Generated Nonce N0: \n");
  serverGenerateNonce(nonce_n0);

    /* Generate and display nonce, N1 */  
  printf("Client Generated Nonce N1: \n");
  clientGenerateNonce(nonce_n1);
 
  /* Generate and display key pair (Ec, Dc) */
   clientGenerateKeyPair();

  /* Generate and display key pair (Es, Ds) */
   serverGenerateKeyPair();

  /* Concatenate client nonce and public key Ec then encrypt */
   clientEncrypt(encrypted_nonce, nonce_n1, crypto_box_ZEROBYTES + 24, nonce_n0);

  /* Server decrypts message from client */
  //  serverDecrypt();

 return NO_ERROR;

}

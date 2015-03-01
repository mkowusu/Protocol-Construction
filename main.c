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
  int result;
  long long int counter;
  char message[INTERNAL_MESSAGE_LENGTH] = "This is the forest primeval ...\n";

  /* Generate and display first time use key pair (Ef, Df)*/
  generateFirstKeyPair();

   /* Generate and display key pair (Es, Ds) */
  serverGenerateKeyPair();

 /* Generate and display key pair (Ec, Dc) */
   clientGenerateKeyPair();

  /* Generate and display nonce, N0 */  
  generateN0();

    /* Generate and display nonce, N1 */  
  generateN1();

  /* Client encrypts n1 */
  clientEncryptN1();

  /* Client concatenates encrypted nonce to public key for server */
    (void) printf("Concatenated encrypted nonce and client public key to send to server:\n");
   clientConcat(crypto_box_ZEROBYTES + 24, crypto_box_PUBLICKEYBYTES, client_concat1, encrypted_n1, client_pk);

  /* Server decrypts message from client */
  //  serverDecrypt();

 return NO_ERROR;

}

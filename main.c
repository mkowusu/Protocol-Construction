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

  /* Generate and display key pair (Es, Ds) */
  serverGenerateKeyPair();

  /* Generate and display key pair (Ec, Dc) */
  clientGenerateKeyPair();

  /* Generate and display nonce, N0 */  
  generateN0();

  /* Generate and display nonce, N1 */  
  generateN1();

  /* concatenate zerobytes to nonce_n1 for encryption */
  zeroBytesN1();

  /* Client encrypts n1 */
  clientEncryptN1();

  /* Client concatenates encrypted nonce to public key for server */
  clientN1Concat();

  /* Server splits encrypted nonce and attached public key */
  (void) printf("Server splits message recieved from client into encrypted nonce and public key:\n");
  serverSplit(client_concat1, encryptedN1_from_client, pk_from_client, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES);

  /* Server decrypts nonce sent from client */
  serverDecryptN1();

  /* Server extracts decrypted nonce from concatenated zeroes */
  serverExtractN1();

  /* Server generates nonce n2 */
  generateN2();

  serverTimeStamp();

  serverResponse1();

  return NO_ERROR;

}

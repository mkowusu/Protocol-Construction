/* Test program for Protocol Construction */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015
*/

#include <stdio.h>
#include <assert.h>
#include "crypto_box.h"
#include "server.h"
#include "client.h"

#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

/* Display the contents of an array of unsigned char values. */

void display_bytes (const unsigned char *byte_vector, long long int length) {
  long long int counter = 0;
  while (counter < length) {
    (void) printf ("02x", byte_vector[counter]);
    (void) putchar((++counter & 0xF) ? ' ' : '\n');
  }
  if (counter & 0xF)
    putchar ('\n');
  putchar('\n');
}

int main() {

 /* Prepare a message for encryption. */

  for (counter = 0; counter < crypto_box_ZEROBYTES; counter++)
    plaintext[counter] = 0;
  for (counter = 0; counter < INTERNAL_MESSAGE_LENGTH; counter++)
    plaintext[crypto_box_ZEROBYTES + counter] = message[counter];

  (void) printf("plaintext:\n");
  display_bytes(plaintext, MESSAGE_LENGTH);

  /* Generate a shared nonce. */

  /* randombytes(shared_nonce, crypto_box_NONCEBYTES); */
  for (counter = 0; counter < crypto_box_NONCEBYTES; counter++)
    shared_nonce[counter] = 0;
  
  (void) printf("shared_nonce:\n");
  display_bytes(shared_nonce, crypto_box_NONCEBYTES);
  
  printf("Testing, Testing... 123");

}

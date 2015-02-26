/* Test program for Protocol Construction */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015
*/

#include <stdio.h>
#include <assert.h>
#include "crypto_box.h"
#include "client.h"
#include "server.h"

 #define INTERNAL_MESSAGE_LENGTH  45
 #define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR  
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

  unsigned char sender_pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sender_sk[crypto_box_SECRETKEYBYTES];
  unsigned char receiver_pk[crypto_box_PUBLICKEYBYTES];
  unsigned char receiver_sk[crypto_box_SECRETKEYBYTES];
  int result;
  long long int counter;
  char message[INTERNAL_MESSAGE_LENGTH] = "This is the forest primeval ...\n";
  unsigned char plaintext[MESSAGE_LENGTH];
  unsigned char ciphertext[MESSAGE_LENGTH];
  unsigned char shared_nonce[crypto_box_NONCEBYTES];
  unsigned char decrypted[MESSAGE_LENGTH];

/* Construct keypairs for sender and receiver. */

  result = crypto_box_keypair(sender_pk, sender_sk);
  assert(result == 0);

  (void) printf("sender_pk:\n");
  display_bytes(sender_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("sender_sk:\n");
  display_bytes(sender_sk, crypto_box_SECRETKEYBYTES);

  result = crypto_box_keypair(receiver_pk, receiver_sk);
  assert(result == 0);

  (void) printf("receiver_pk:\n");
  display_bytes(receiver_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("receiver_sk:\n");
  display_bytes(receiver_sk, crypto_box_SECRETKEYBYTES);


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

 return 0;

}
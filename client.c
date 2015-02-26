/* Test program for crypto_box utilities */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015
*/

#include <stdio.h>
#include <assert.h>
#include "crypto_box.h"
#include "server.h"

 #define INTERNAL_MESSAGE_LENGTH  45
 #define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR  

unsigned char sender_pk[crypto_box_PUBLICKEYBYTES];
unsigned char sender_sk[crypto_box_SECRETKEYBYTES];
int result;
long long int counter;
char message[INTERNAL_MESSAGE_LENGTH] = "This is the forest primeval ...\n";
unsigned char plaintext[MESSAGE_LENGTH];
unsigned char ciphertext[MESSAGE_LENGTH];
unsigned char shared_nonce[crypto_box_NONCEBYTES];
unsigned char decrypted[MESSAGE_LENGTH];

/* Returns a char* array containing nonce */
char* clientGenerateNonce() {

}

/* Returns a struct containing key pair */
void clientGenerateKeyPair() {

  /* Construct keypairs for sender. */

  result = crypto_box_keypair(sender_pk, sender_sk);
  assert(result == 0);

  (void) printf("sender_pk:\n");
  display_bytes(sender_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("sender_sk:\n");
  display_bytes(sender_sk, crypto_box_SECRETKEYBYTES);


}

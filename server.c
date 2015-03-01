/* Test program for crypto_box utilities */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015
*/

#include <stdio.h>
#include <assert.h>
#include <crypto_box.h>
#include "client.h"  

unsigned char server_pk[crypto_box_PUBLICKEYBYTES];
unsigned char server_sk[crypto_box_SECRETKEYBYTES];
long long int counter;
unsigned char nonce_n0[crypto_box_NONCEBYTES];
unsigned char serverDecrypted[MESSAGE_LENGTH];

  /* Generate and display server nonce*/
void serverGenerateNonce(unsigned char nonce[crypto_box_NONCEBYTES]) {

  /* randombytes(shared_nonce, crypto_box_NONCEBYTES); */
  for (counter = 0; counter < crypto_box_NONCEBYTES; counter++)
    nonce[counter] = 0;

  display_bytes(nonce, crypto_box_NONCEBYTES);
}

/* Returns a struct containing key pair */
void serverGenerateKeyPair() {

  /* Construct keypairs for sender. */

  result = crypto_box_keypair(server_pk, server_sk);
  assert(result == 0);

  (void) printf("Server Public Key:\n");
  display_bytes(server_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("Server Secret Key:\n");
  display_bytes(server_sk, crypto_box_SECRETKEYBYTES);

}

void serverDecrypt(unsigned char* nonce) {

  /* Decrypt the message at the receiving end.

     crypto_box returns a value that begins with crypto_box_BOXZEROBYTES
     zero bytes, and so satisfies the precondition for crypto_box_open.
  */

  result = crypto_box_open(serverDecrypted, clientCiphertext, MESSAGE_LENGTH, nonce, client_pk, server_sk);
  assert(result == 0);

  (void) printf("Decrypted Message:\n");
  display_bytes(serverDecrypted, MESSAGE_LENGTH);

}

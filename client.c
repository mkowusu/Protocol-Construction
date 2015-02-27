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
#define NO_ERROR                 0

unsigned char sender_pk[crypto_box_PUBLICKEYBYTES];
unsigned char sender_sk[crypto_box_SECRETKEYBYTES];
int result;
long long int counter;
unsigned char plaintext[MESSAGE_LENGTH];
unsigned char clientCiphertext[MESSAGE_LENGTH];
unsigned char client_nonce[crypto_box_NONCEBYTES];
unsigned char decrypted[MESSAGE_LENGTH];

  /* Generate and display client nonce*/
void clientGenerateNonce() {

  /* randombytes(client_nonce, crypto_box_NONCEBYTES); */
  for (counter = 0; counter < crypto_box_NONCEBYTES; counter++)
    client_nonce[counter] = 0;

  display_bytes(client_nonce, crypto_box_NONCEBYTES);
}

  /* Generate and display key pair (Ec, Dc) */
void clientGenerateKeyPair() {

  /* Construct keypairs for sender. */

  result = crypto_box_keypair(sender_pk, sender_sk);
  assert(result == 0);

  (void) printf("Sender Public Key:\n");
  display_bytes(sender_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("Sender Secret Key:\n");
  display_bytes(sender_sk, crypto_box_SECRETKEYBYTES);


}

  /* Concatenate client nonce and public key Ec then encrypt */
  /* Display ciphertext */
void clientEncrypt(){

  (void) printf("Plaintext as seen by client:\n");
  display_bytes(plaintext, MESSAGE_LENGTH);

  result = crypto_box(clientCiphertext, plaintext, MESSAGE_LENGTH, client_nonce, receiver_pk, sender_sk);
  assert(result == 0);

  (void) printf("Encrpyted Message:\n");
  display_bytes(clientCiphertext, MESSAGE_LENGTH);

}

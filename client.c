/* Test program for crypto_box utilities */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015
*/

#include <stdio.h>
#include <assert.h>
#include <crypto_box.h>
#include "server.h"

#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

unsigned char client_pk[crypto_box_PUBLICKEYBYTES];
unsigned char client_sk[crypto_box_SECRETKEYBYTES];
int result;
long long int counter;
unsigned char plaintext[MESSAGE_LENGTH];
unsigned char clientCiphertext[MESSAGE_LENGTH];
unsigned char nonce_n1[crypto_box_NONCEBYTES];
unsigned char decrypted[MESSAGE_LENGTH];
unsigned char encrypted_nonce[crypto_box_NONCEBYTES];
unsigned char client_concat[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];

  /* Generate and display client nonce*/
void clientGenerateNonce(unsigned char nonce[crypto_box_NONCEBYTES]) {

  /* randombytes(client_nonce, crypto_box_NONCEBYTES); */
  for (counter = 0; counter < crypto_box_NONCEBYTES; counter++)
    nonce[counter] = 0;

  display_bytes(nonce, crypto_box_NONCEBYTES);
}

  /* Generate and display key pair (Ec, Dc) */
void clientGenerateKeyPair() {

  /* Construct keypairs for sender. */

  result = crypto_box_keypair(client_pk, client_sk);
  assert(result == 0);

  (void) printf("Sender Public Key:\n");
  display_bytes(client_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("Sender Secret Key:\n");
  display_bytes(client_sk, crypto_box_SECRETKEYBYTES);


}

  /* Concatenate client nonce and public key Ec then encrypt */
  /* Display ciphertext */
void clientEncrypt(char* encrypted, char* toEncrypt, int length, char* nonce){

  result = crypto_box(encrypted, toEncrypt, length, nonce, server_pk, client_sk);
  assert(result == 0);

  (void) printf("Encrpyted item:\n");
  display_bytes(encrypted, crypto_box_ZEROBYTES + 24);

}

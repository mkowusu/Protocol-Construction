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
unsigned char first_pk[crypto_box_PUBLICKEYBYTES];
unsigned char first_sk[crypto_box_SECRETKEYBYTES];
long long int counter;
unsigned char nonce_n0[crypto_box_NONCEBYTES];
unsigned char nonce_n2[crypto_box_NONCEBYTES];
unsigned char serverDecrypted[MESSAGE_LENGTH];

  /* Generic function to generate server nonces */
void serverGenerateNonce(unsigned char* nonce) {

  for (counter = 0; counter < crypto_box_NONCEBYTES; counter++)
    nonce[counter] = 0;

  display_bytes(nonce, crypto_box_NONCEBYTES);
}

void generateN0() {

  (void) printf("Client generated nonce, N0:\n");
  serverGenerateNonce(nonce_n0);

}

void generateN2() {

  (void) printf("Client generated nonce, N2:\n");
  serverGenerateNonce(nonce_n2);

}

/* Generates first-time use key pair */
void generateFirstKeyPair() {

  /* Construct keypairs for sender. */

  result = crypto_box_keypair(server_pk, server_sk);
  assert(result == 0);

  (void) printf("\nFirst Time Use Public Key:\n");
  display_bytes(server_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("First Time Use Secret Key:\n");
  display_bytes(server_sk, crypto_box_SECRETKEYBYTES);

}

/* Generates server's key pair */
void serverGenerateKeyPair() {

  /* Construct keypairs for sender. */

  result = crypto_box_keypair(first_pk, first_sk);
  assert(result == 0);

  (void) printf("Server Public Key:\n");
  display_bytes(first_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("Server Secret Key:\n");
  display_bytes(first_sk, crypto_box_SECRETKEYBYTES);

}

  /* Server function for encryption */
void serverEncrypt(char* encrypted, char* toEncrypt, int length, char* nonce, char* pk, char* sk){

  result = crypto_box(encrypted, toEncrypt, length, nonce, pk, sk);
  assert(result == 0);

}

void serverDecrypt(unsigned char* decrypted, unsigned char* nonce) {

  /* Decrypt the message at the receiving end.

     crypto_box returns a value that begins with crypto_box_BOXZEROBYTES
     zero bytes, and so satisfies the precondition for crypto_box_open.
  */

  result = crypto_box_open(decrypted, clientCiphertext, MESSAGE_LENGTH, nonce, client_pk, server_sk);
  assert(result == 0);

  (void) printf("Decrypted Message:\n");
  display_bytes(serverDecrypted, MESSAGE_LENGTH);

}

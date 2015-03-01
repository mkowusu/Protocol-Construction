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
unsigned char encryptedN1_from_client[crypto_box_NONCEBYTES];
unsigned char nonce_n2[crypto_box_NONCEBYTES];
unsigned char pk_from_client[crypto_box_PUBLICKEYBYTES];
unsigned char decrypted_n1[crypto_box_NONCEBYTES + crypto_box_ZEROBYTES];

  /* Generic function to generate server nonces */
void serverGenerateNonce(unsigned char* nonce) {

  for (counter = 0; counter < crypto_box_NONCEBYTES; counter++)
    nonce[counter] = 0;

  display_bytes(nonce, crypto_box_NONCEBYTES);
}

void generateN0() {

  (void) printf("Server generated nonce, N0:\n");
  serverGenerateNonce(nonce_n0);

}

void generateN2() {

  (void) printf("Server generated nonce, N2:\n");
  serverGenerateNonce(nonce_n2);

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

void serverSplit(unsigned char* input, unsigned char* a, unsigned char* b, int splitPoint, int length) {

  for (counter = 0; counter < splitPoint; counter++)
  a[counter] = input[counter];

int b_place = 0;

for (counter = counter; counter < length; counter++){
  b[b_place] = input[counter];
    b_place++;

 }

  (void) printf("String 1:\n");
  display_bytes(a, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);

  (void) printf("String 2:\n");
  display_bytes(b, crypto_box_PUBLICKEYBYTES);

}

void serverDecrypt(unsigned char* decrypted, unsigned char * cipher_text, int length, unsigned char* nonce, unsigned char* pk, unsigned char* sk) {

  /* Decrypt the message at the receiving end.

     crypto_box returns a value that begins with crypto_box_BOXZEROBYTES
     zero bytes, and so satisfies the precondition for crypto_box_open.
  */

  result = crypto_box_open(decrypted, cipher_text, length, nonce, pk, sk);
  assert(result == 0);

  (void) printf("Decrypted Message:\n");
  display_bytes(decrypted, length);

}

void serverDecryptN1() {

  serverDecrypt(decrypted_n1, encryptedN1_from_client, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES, nonce_n0, client_pk, server_sk);

}  

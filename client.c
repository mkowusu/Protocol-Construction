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
unsigned char nonce_n3[crypto_box_NONCEBYTES];
unsigned char decrypted[MESSAGE_LENGTH];
unsigned char encrypted_n1[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES];
unsigned char client_concat1[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];
unsigned char nonceN1_with_zerobytes[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES];

  /* Generic function to generate client nonces */
void clientGenerateNonce(unsigned char* nonce) {

randombytes(nonce, crypto_box_NONCEBYTES);

  display_bytes(nonce, crypto_box_NONCEBYTES);
}

/* Function to generate nonce n1 */
void generateN1() {

  (void) printf("Client generated nonce, N1:\n");
  clientGenerateNonce(nonce_n1);

}

/* Function to generate nonce n3 */
void generateN3() {

  (void) printf("Client generated nonce, N3:\n");
  clientGenerateNonce(nonce_n3);

}

  /* Generate and display key pair (Ec, Dc) */
void clientGenerateKeyPair() {

  /* Construct keypairs for sender. */
  result = crypto_box_keypair(client_pk, client_sk);
  assert(result == 0);

  (void) printf("Client Public Key:\n");
  display_bytes(client_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("Client Secret Key:\n");
  display_bytes(client_sk, crypto_box_SECRETKEYBYTES);

}

  /* Client function for encryption */
void clientEncrypt(char* encrypted, char* toEncrypt, int length, char* nonce, char* pk, char* sk){

  result = crypto_box(encrypted, toEncrypt, length, nonce, pk, sk);
  assert(result == 0);

}

/* Function to encrypt and display N1 */
void clientEncryptN1() {

clientEncrypt(encrypted_n1, nonceN1_with_zerobytes, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES, nonce_n0, server_pk, client_sk);

  (void) printf("Encrypted N1:\n");
  display_bytes(encrypted_n1, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);
}

/* Client function to concatenate two strings together */
void clientConcat(int lengthA, int lengthB, unsigned char* output, unsigned char* a, unsigned char* b){

    for (counter = 0; counter < lengthA; counter++)
    output[counter] = a[counter];

    int b_place = 0;

    for (counter = counter; counter < lengthA + lengthB; counter++){
      output[counter] = b[b_place];
      b_place++;
    }

    (void) printf("Concatenated item:\n");
    display_bytes(output, lengthA + lengthB);
}

void zeroBytesConcat(char* item, char* newItem, int length){

    for (counter = 0; counter < crypto_box_ZEROBYTES; counter++)
    newItem[counter] = 0;

    int item_place = 0;

    for (counter = counter; counter < length; counter++){
      newItem[counter] = item[item_place];
      item_place++;
    }

    (void) printf("Concatenated item:\n");
    display_bytes(newItem, length);
}

/* function to add crypto_box_ZEROBYTES number of 0s to beginning on N1 */
void zeroBytesN1(){

  zeroBytesConcat(nonce_n1, nonceN1_with_zerobytes, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);

}

void clientN1Concat() {

   clientConcat(crypto_box_ZEROBYTES + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES, client_concat1, encrypted_n1, client_pk);

}

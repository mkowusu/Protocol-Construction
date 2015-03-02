/* Test program for crypto_box utilities */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015
*/

#include <stdio.h>
#include <assert.h>
#include <crypto_box.h>
#include <time.h>
#include "client.h"  

#define SIZE_OF_TIME_T           10

unsigned char server_pk[crypto_box_PUBLICKEYBYTES];
unsigned char server_sk[crypto_box_SECRETKEYBYTES];
long long int counter;
unsigned char nonce_n0[crypto_box_NONCEBYTES];
unsigned char encryptedN1_from_client[crypto_box_NONCEBYTES];
unsigned char nonce_n2[crypto_box_NONCEBYTES];
unsigned char pk_from_client[crypto_box_PUBLICKEYBYTES];
unsigned char decrypted_n1_ZEROBYTES[crypto_box_NONCEBYTES + crypto_box_ZEROBYTES];
unsigned char decrypted_n1[crypto_box_NONCEBYTES];
time_t server_time;
unsigned char time_string[SIZE_OF_TIME_T];
unsigned char server_message_1[SIZE_OF_TIME_T + (crypto_box_NONCEBYTES * 2) + crypto_box_ZEROBYTES];

/* Generate N0 0 nonce for initial communication */
void generateN0() {
  (void) printf("Server generated nonce, N0:\n");
  for (counter = 0; counter < crypto_box_NONCEBYTES; counter++)
    nonce_n0[counter] = 0;

  display_bytes(nonce_n0, crypto_box_NONCEBYTES);

}

void generateN2() {
  (void) printf("Server generated nonce, N2:\n");
  randombytes(nonce_n2, crypto_box_NONCEBYTES);

  display_bytes(nonce_n2, crypto_box_NONCEBYTES);
}

/* Generates server's key pair */
void serverGenerateKeyPair() {

  /* Construct keypairs for server. */
  result = crypto_box_keypair(server_pk, server_sk);
  assert(result == 0);

  (void) printf("\nServer Public Key:\n");
  display_bytes(server_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("Server Secret Key:\n");
  display_bytes(server_sk, crypto_box_SECRETKEYBYTES);

}

/* Server function for encryption */
void serverEncrypt(char* encrypted, char* toEncrypt, int length, char* nonce, char* pk, char* sk){

  result = crypto_box(encrypted, toEncrypt, length, nonce, sk, pk);
  assert(result == 0);

}

/* Function to separate one char array into two */
void serverSplit(unsigned char* input, unsigned char* a, unsigned char* b, int splitPoint, int length) {

  for (counter = 0; counter < splitPoint; counter++)
    a[counter] = input[counter];

  int b_place = 0;

  for (counter = counter; counter < length; counter++){
    b[b_place] = input[counter];
    b_place++;

  }

  (void) printf("String 1:\n");
  display_bytes(a, splitPoint);

  (void) printf("String 2:\n");
  display_bytes(b, length-splitPoint);

}

/* Function to extract a portion of a char array into new array */
void serverExtract(unsigned char* input, unsigned char* output, int begin, int end) {

  int place = 0; /* variable to hold place of input char being written to */
  for (counter = begin; counter < end; counter++){
    output[place] = input[counter];
    place++;
  }

}

void serverExtractN1(){

  /* Call serverExtract from server end where the data for decrypted nonce N1 is stored */
  serverExtract(decrypted_n1_ZEROBYTES, decrypted_n1, crypto_box_ZEROBYTES, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);

  (void) printf("Final nonce n1, decrypted and extracted by server:\n");
  display_bytes(decrypted_n1, crypto_box_NONCEBYTES);
}

/* Generic server function for decryption */
void serverDecrypt(unsigned char* decrypted, unsigned char * cipher_text, int length, unsigned char* nonce, unsigned char* pk, unsigned char* sk) {

  /* Decrypt the message at the receiving end.

     crypto_box returns a value that begins with crypto_box_BOXZEROBYTES
     zero bytes, and so satisfies the precondition for crypto_box_open.
  */

  result = crypto_box_open(decrypted, cipher_text, length, nonce, pk, sk);
  assert(result == 0);

}

/* Function to decrypt nonce n1 using public key recieved from client */
void serverDecryptN1() {

  serverDecrypt(decrypted_n1_ZEROBYTES, encryptedN1_from_client, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES, nonce_n0, pk_from_client, server_sk);

  (void) printf("Server decrypted nonce, N1, recieved from client including ZEROBYTES 0s:\n");
  display_bytes(decrypted_n1_ZEROBYTES, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);

} 

/* Server function to generate time stamp */
void serverTimeStamp() {

  (void) printf("Server time in seconds:\n");
  server_time = time(NULL);
  sprintf(time_string, "%ld", server_time);
  printf("%s\n\n", time_string);
}

void verifyTime() {

  int time = atoi(time_string);

}

void serverResponse1(){

  /* Add zeroes to beginning of message to be encrypted */
  for (counter = 0; counter < crypto_box_ZEROBYTES; counter++)
    server_message_1[counter] = 0;

  int place; /* Place holder */

  for (counter = counter; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter++)
    server_message_1[counter] = decrypted_n1[place++];

  place = 0; /* reset placeholder */

  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2); counter++)
    server_message_1[counter] = nonce_n2[place++];

  place = 0; /* reset placeholder */

  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T; counter++)
    server_message_1[counter] = time_string[place++];

    (void) printf("Message to be sent to client in plaintext:\n");
 display_bytes(server_message_1, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T );
}

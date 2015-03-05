/* Test program for crypto_box utilities */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015
*/

#include <stdio.h>
#include <assert.h>
#include <crypto_box.h>
#include <time.h>
#include "server.h"

#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

unsigned char client_pk[crypto_box_PUBLICKEYBYTES];
unsigned char client_sk[crypto_box_SECRETKEYBYTES];
int result;
long long int counter;
unsigned char clientCiphertext[MESSAGE_LENGTH]; // weird 
unsigned char nonce_n1[crypto_box_NONCEBYTES];
unsigned char nonce_n3[crypto_box_NONCEBYTES];
unsigned char decrypted[MESSAGE_LENGTH];
unsigned char encrypted_n1[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES];
unsigned char client_concat1[crypto_box_NONCEBYTES + crypto_box_ZEROBYTES + crypto_box_PUBLICKEYBYTES];
unsigned char nonceN1_with_zerobytes[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES];
unsigned char decrypted_message_1[SIZE_OF_TIME_T + (crypto_box_NONCEBYTES * 2) + crypto_box_ZEROBYTES];
unsigned char nonce_n2[crypto_box_NONCEBYTES];
unsigned char client_response[crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH];
unsigned char client_response_encrypted[crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH];
/* Union to store time value as time_t and an unsigned char of bytes */
union timestamp {
  time_t native; 
  unsigned char bytes[sizeof(time_t)];
};

union timestamp server_time; /* store recieved timestamp */
union timestamp client_time; /* store generated timestamp */

union message {
  char* native;//[INTERNAL_MESSAGE_LENGTH]; 
  unsigned char bytes[INTERNAL_MESSAGE_LENGTH];
};


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

  (void) printf("Encrypted N1 with ZEROBYTES 0s:\n");
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
}

void zeroBytesConcat(char* item, char* newItem, int length){

  for (counter = 0; counter < crypto_box_ZEROBYTES; counter++)
    newItem[counter] = 0;

  int item_place = 0;

  for (counter = counter; counter < length; counter++){
    newItem[counter] = item[item_place];
    item_place++;
  }

}

/* function to add crypto_box_ZEROBYTES number of 0s to beginning on N1 */
void zeroBytesN1(){

  zeroBytesConcat(nonce_n1, nonceN1_with_zerobytes, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);

  (void) printf("N1 with ZEROBYTES number of 0s:\n");
  display_bytes(nonceN1_with_zerobytes, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);
}

void clientN1Concat() {

  clientConcat(crypto_box_ZEROBYTES + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES, client_concat1, encrypted_n1, client_pk);

  (void) printf("Encrypted nonce, N1, and client public key concatenated to send to server:\n");
  display_bytes(client_concat1, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES);

}

/* Generic client function for decryption */
void clientDecrypt(unsigned char* decrypted, unsigned char * cipher_text, int length, unsigned char* nonce, unsigned char* pk, unsigned char* sk) {

  /* Decrypt the message at the receiving end.

     crypto_box returns a value that begins with crypto_box_BOXZEROBYTES
     zero bytes, and so satisfies the precondition for crypto_box_open.
  */

  result = crypto_box_open(decrypted, cipher_text, length, nonce, pk, sk);
  assert(result == 0);

}

/* Function to decrypt nonce n1 using public key recieved from client */
void clientDecryptMessage1() {

  clientDecrypt(decrypted_message_1, encrypted_server_message_1, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T, nonce_n1, server_pk, client_sk);

  (void) printf("Client decrypted message:\n");
  display_bytes(decrypted_message_1, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T);

} 


/* Function to extract N2 and timestamp from server message 1 */
void extractN2Time() {

  int place = 0; /* int to hold the place of the char being written to */

  /* Save bytes from nonce_n2 in decrypted message in a new char array */
  for (counter = crypto_box_NONCEBYTES + crypto_box_ZEROBYTES; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2); counter++)
    nonce_n2[place++] = decrypted_message_1[counter];

  /* Display nonce_n2 extracted from server message */
  (void) printf("Nonce N2 extracted from server response 1:\n");
  display_bytes(nonce_n2, crypto_box_NONCEBYTES);

  place = 0; /* reset placeholder */

  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T; counter++)

    server_time.bytes[place++] = decrypted_message_1[counter];


  /* Display extracted from time stamp in bytes and seconds*/
  (void) printf("Server time in seconds:\n");
  (void) printf("%ld\n\n", server_time.native);

  (void) printf("Time stamp extracted from server response 1:\n");
  display_bytes(server_time.bytes, SIZE_OF_TIME_T);

}

void compareTimeStamps () {

  client_time.native = time(NULL);

  (void) printf("Client time in seconds:\n");
  (void) printf("%ld\n\n", client_time.native);

  if ((client_time.native - server_time.native) > 90) {
    (void) printf("Timestamp authentication unsuccessful!\n");
    return;
  }
  else (void) printf("Timestamp authentication successful.\n\n");
}

void clientResponse () {

  union message question;
  question.native = "What's up?";

  /* Add zeroes to beginning of message to be encrypted */
  for (counter = 0; counter < crypto_box_ZEROBYTES; counter++)
    client_response[counter] = 0;

  int place; /* placeholder */

  /* concatenate N2 to the zerobyte message */
  for (counter = counter; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter++)
    client_response[counter] = nonce_n2[place++];

  place = 0; /* reset placeholder */

  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2); counter++)
    client_response[counter] = nonce_n3[place++];

  place = 0; /* reset placeholder */

  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH; counter++)
    client_response[counter] = question.bytes[place++];

  (void) printf("Message containing question to be sent from client to server: \n");
  display_bytes(client_response, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH);

  /* Encrypt concatenation of nonce 2, nonce 3 and question */
  clientEncrypt(client_response_encrypted, client_response, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH, nonce_n2, server_pk, client_sk);  

  (void) printf("Encrypted Question to send to Server: \n");
  display_bytes(client_response_encrypted, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH);
}

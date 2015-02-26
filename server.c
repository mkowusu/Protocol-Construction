/* Test program for crypto_box utilities */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015
*/

#include <stdio.h>
#include <assert.h>
#include "crypto_box.h"
#include "client.h"


 #define INTERNAL_MESSAGE_LENGTH  45
 #define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR  

unsigned char receiver_pk[crypto_box_PUBLICKEYBYTES];
unsigned char receiver_sk[crypto_box_SECRETKEYBYTES];
int result;
long long int counter;
unsigned char plaintext[MESSAGE_LENGTH];
unsigned char ciphertext[MESSAGE_LENGTH];
unsigned char shared_nonce[crypto_box_NONCEBYTES];
unsigned char decrypted[MESSAGE_LENGTH];

/* Returns a char* array containing nonce */
char* serverGenerateNonce() {

}

/* Returns a struct containing key pair */
void serverGenerateKeyPair() {

}

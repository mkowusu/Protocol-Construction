/* Test program for crypto_box utilities */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015
*/


/* Information in this header file contain data that the client effectively sends to the system for interacting with the server */

#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

unsigned char clientCiphertext[MESSAGE_LENGTH];

void generateN1();

void clientGenerateKeyPair();

void clientEncrypt();

void clientN1Concat();

int result;

void zeroBytesN1();

unsigned char client_concat1[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];

/* Test program for crypto_box utilities */

/* Michael Owusu
   Camila Mateo

   created February 25, 2015
*/


/* Information in this header file contain data that the server effectively sends to the system for interacting with the client */

#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

unsigned char server_pk[crypto_box_PUBLICKEYBYTES];
unsigned char nonce_n0[crypto_box_NONCEBYTES];
unsigned char encryptedN1_from_client[crypto_box_NONCEBYTES];
unsigned char decryptedN1_from_client[crypto_box_NONCEBYTES];
unsigned char pk_from_client[crypto_box_PUBLICKEYBYTES];

void serverSplit(unsigned char* input, unsigned char* a, unsigned char* b, int splitPoint, int length);
void serverGenerateKeyPair();
void generateN0();
void generateN2();
void serverDecryptN1();
void serverExtractN1();
void serverTimeStamp();
void verifyTime();
void serverResponse1();

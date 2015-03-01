#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

unsigned char server_pk[crypto_box_PUBLICKEYBYTES];
unsigned char server_sk[crypto_box_SECRETKEYBYTES];
unsigned char serverDecrypted[MESSAGE_LENGTH];
unsigned char nonce_n0[crypto_box_NONCEBYTES];

void serverGenerateKeyPair();
void serverGenerateNonce(char nonce[crypto_box_NONCEBYTES]);
void serverDecrypt();


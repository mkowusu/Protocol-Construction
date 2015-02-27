#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

unsigned char receiver_pk[crypto_box_PUBLICKEYBYTES];
unsigned char receiver_sk[crypto_box_SECRETKEYBYTES];
unsigned char serverDecrypted[MESSAGE_LENGTH];

void serverGenerateKeyPair();
void serverGenerateNonce();
void serverDecrypt();


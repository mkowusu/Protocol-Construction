#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

unsigned char server_pk[crypto_box_PUBLICKEYBYTES];
unsigned char first_pk[crypto_box_PUBLICKEYBYTES];
unsigned char first_sk[crypto_box_SECRETKEYBYTES];
unsigned char nonce_n0[crypto_box_NONCEBYTES];
unsigned char encryptedN1_from_client[crypto_box_NONCEBYTES];
unsigned char decryptedN1_from_client[crypto_box_NONCEBYTES];
unsigned char pk_from_client[crypto_box_PUBLICKEYBYTES];

void serverSplit(unsigned char* input, unsigned char* a, unsigned char* b, int splitPoint, int length);
void serverGenerateKeyPair();
void generateN0();
void generateN2();
void serverDecryptN0();

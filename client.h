#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

unsigned char clientCiphertext[MESSAGE_LENGTH];

unsigned char client_pk[crypto_box_PUBLICKEYBYTES];

void generateN1();

void clientGenerateKeyPair();

void clientEncrypt();

void clientN1Concat();

int result;

void zeroBytesN1();

unsigned char client_concat1[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];

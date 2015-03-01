#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

unsigned char clientCiphertext[MESSAGE_LENGTH];

unsigned char client_pk[crypto_box_PUBLICKEYBYTES];

unsigned char encrypted_n1[crypto_box_NONCEBYTES];

void generateN1();

void clientGenerateKeyPair();

void clientEncrypt();

int result;

unsigned char client_concat1[crypto_box_ZEROBYTES + 24 + crypto_box_PUBLICKEYBYTES];

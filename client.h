#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0

unsigned char clientCiphertext[MESSAGE_LENGTH];

unsigned char nonce_n1[crypto_box_NONCEBYTES];

unsigned char client_pk[crypto_box_PUBLICKEYBYTES];

unsigned char client_sk[crypto_box_SECRETKEYBYTES];

unsigned char encrypted_nonce[crypto_box_NONCEBYTES];

unsigned char plaintext[MESSAGE_LENGTH];

void clientGenerateNonce();

void clientGenerateKeyPair();

void clientEncrypt();

int result;

unsigned char client_concatenation[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];

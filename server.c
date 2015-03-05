/* Test program for crypto_box utilities 

   Michael Owusu
   Camila Mateo

   created February 25, 2015
*/

#include <stdio.h>
#include <assert.h>
#include <crypto_box.h>
#include <time.h>
#include "client.h"  

int result; /* assertion for cryptobox */
int place; /* additional counter */
long long int counter; /* counter for assigning bytes to char arrays */

/* server generated keypair */
unsigned char server_pk[crypto_box_PUBLICKEYBYTES];
unsigned char server_sk[crypto_box_SECRETKEYBYTES];

/* server generated zero nonce */
unsigned char nonce_n0[crypto_box_NONCEBYTES];

/* store encrypted nonce N1 parsed from client */
unsigned char encryptedN1_from_client[crypto_box_NONCEBYTES];
unsigned char nonce_n2[crypto_box_NONCEBYTES];
unsigned char pk_from_client[crypto_box_PUBLICKEYBYTES];
unsigned char decrypted_n1_ZEROBYTES[crypto_box_NONCEBYTES + crypto_box_ZEROBYTES];
unsigned char decrypted_n1[crypto_box_NONCEBYTES];
unsigned char time_string[SIZE_OF_TIME_T];
unsigned char server_message_1[SIZE_OF_TIME_T + (crypto_box_NONCEBYTES * 2) + crypto_box_ZEROBYTES];
unsigned char encrypted_server_message_1[SIZE_OF_TIME_T + (crypto_box_NONCEBYTES * 2) + crypto_box_ZEROBYTES];
unsigned char client_question_decrypted[crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH];
unsigned char nonce_n3[crypto_box_NONCEBYTES];
unsigned char server_answer[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + INTERNAL_MESSAGE_LENGTH];
unsigned char encrypted_server_answer[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + INTERNAL_MESSAGE_LENGTH];

/* Union to store time value as time_t and an unsigned char of bytes */
union timestamp {
  time_t native; 
  unsigned char bytes[sizeof(time_t)];
};

union timestamp server_time;
union timestamp client_time;

union message {
  char* native;//[INTERNAL_MESSAGE_LENGTH]; 
  unsigned char bytes[INTERNAL_MESSAGE_LENGTH];
};

union message question;  
union message answer;

/* Generate nonce 0 for initial communication */
void generateN0() {
  (void) printf("Server generated nonce, N0:\n");
  for (counter = 0; counter < crypto_box_NONCEBYTES; counter++)
    nonce_n0[counter] = 0;

  display_bytes(nonce_n0, crypto_box_NONCEBYTES);
}

/* Generates server's key pair */
void serverGenerateKeyPair() {

  /* Construct keypairs for server. */
  result = crypto_box_keypair(server_pk, server_sk);
  assert(result == 0);

  (void) printf("\nServer Public Key:\n");
  display_bytes(server_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("Server Secret Key:\n");
  display_bytes(server_sk, crypto_box_SECRETKEYBYTES);
}

void serverInitialResponse() {

  /* Server splits encrypted nonce and attached public key */
  (void) printf("Server splits message recieved from client into encrypted nonce and public key:\n");

  /* Separates encrypted nonce 1 */
  for (counter = 0; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter++)
    encryptedN1_from_client[counter] = initial_message[counter];

  place = 0; /* Initialize placeholder */

  /* Separates client public key */
  for (counter = counter; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES; counter++)
    pk_from_client[place++] = initial_message[counter];

  /* Print separated encrypted nonce 1 and client public key  */
  (void) printf("Encrypted nonce 1 from client:\n");
  display_bytes(encryptedN1_from_client,  crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);

  (void) printf("Client public key identified by server:\n");
  display_bytes(pk_from_client, crypto_box_PUBLICKEYBYTES);

  /* Decrypt the encrypted nonce 1 */
  result = crypto_box_open(decrypted_n1_ZEROBYTES, encryptedN1_from_client, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES, nonce_n0, pk_from_client, server_sk);
  assert(result == 0);

  /* Print decrypted nonce 1 */
  (void) printf("Server decrypted nonce 1, recieved from client including ZEROBYTES 0s:\n");
  display_bytes(decrypted_n1_ZEROBYTES, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);

  place = 0; /* reset placeholder */

  /* Separate decrypted nonce 1 from concatenated ZEROBYTES */
  for (counter = crypto_box_ZEROBYTES; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter++)
    decrypted_n1[place++] = decrypted_n1_ZEROBYTES[counter];

  (void) printf("Final nonce n1, decrypted and extracted by server:\n");
  display_bytes(decrypted_n1, crypto_box_NONCEBYTES);

  /* Generate nonce 2 */
  (void) printf("Server generated nonce, N2:\n");
  randombytes(nonce_n2, crypto_box_NONCEBYTES);

  display_bytes(nonce_n2, crypto_box_NONCEBYTES);

  /* Generate time stamp */
  server_time.native = time(NULL);

  (void) printf("Server time in seconds:\n");
  (void) printf("%ld\n", server_time.native);

  (void) printf("Server time in bytes:\n");
  display_bytes(server_time.bytes, SIZE_OF_TIME_T);

  /* Start generating response message to be sent to client */
  /* Add zeroes to beginning of message to be encrypted */
  for (counter = 0; counter < crypto_box_ZEROBYTES; counter++)
    server_message_1[counter] = 0;

  place = 0;; /* reset placeholder */

  /* Adding nonce 1 to message */
  for (counter = counter; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter++)
    server_message_1[counter] = decrypted_n1[place++];

  place = 0; /* reset placeholder */

  /* Adding nonce 2 to message */
  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2); counter++)
    server_message_1[counter] = nonce_n2[place++];

  place = 0; /* reset placeholder */

  /* Adding timestamp to message */
  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T; counter++)
    server_message_1[counter] = server_time.bytes[place++];

  /* Print final message to be sent to client */
  (void) printf("Message to be sent to client in plaintext:\n");
  display_bytes(server_message_1, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T );

  /* Encrypt message */
  result = crypto_box(encrypted_server_message_1, server_message_1, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T, decrypted_n1, pk_from_client, server_sk);
  assert(result == 0);

  (void) printf("Encrypted Message to send to client:\n");
  display_bytes(encrypted_server_message_1, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T );
}

void serverAnswerQuestion() {

  /* Decrypt the message at the receiving end */
  result = crypto_box_open(client_question_decrypted, client_question_encrypted, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH, nonce_n2, pk_from_client, server_sk);
  assert(result == 0);

  (void) printf("Server decrypted nonce 2, nonce 3, and question received by Client:\n");
  display_bytes(client_question_decrypted, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH);

  place = 0; /* reset placeholder */

  /* Separate decrypted nonce 3 from message received from client */
  for (counter = crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES *2); counter++)
    nonce_n3[place++] = client_question_decrypted[counter];

  (void) printf("Nonce 3 sent by Client and received by Server:\n");
  display_bytes(nonce_n3, crypto_box_NONCEBYTES);

  place = 0; /* reset placeholder */

  /* Separate question from message received from client */
  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES *2) + INTERNAL_MESSAGE_LENGTH; counter++)
    question.bytes[place++] = client_question_decrypted[counter];

  (void) printf("Question sent by Client and received by Server in bytes:\n");
  display_bytes(question.bytes, INTERNAL_MESSAGE_LENGTH);

  (void) printf("Question received in plaintext: \n");
  (void) printf("%s\n\n", question.native);

  /* Initialize answer  */
  answer.native = "Not much.";

  /* Start generating message that contains answer to question sent by client */
  /* Add zeroes to beginning of message to be encrypted */
  for (counter = 0; counter < crypto_box_ZEROBYTES; counter++)
    server_answer[counter] = 0;

  place = 0; /* reset placeholder */

  /* Add nonce 3 to message */
  for (counter = counter; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter++)
    server_answer[counter] = nonce_n3[place++];

  place = 0; /* reset placeholder */

  /* Add question's answer to message */
  for (counter = counter; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + INTERNAL_MESSAGE_LENGTH; counter++)
    server_answer[counter] = answer.bytes[place++];  

  (void) printf("Message containing answer to be sent from server to client: \n");
  display_bytes(server_answer, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + INTERNAL_MESSAGE_LENGTH);

  /* Encrypt message */
  result = crypto_box(encrypted_server_answer, server_answer, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + INTERNAL_MESSAGE_LENGTH, nonce_n3, pk_from_client, server_sk);
  assert(result == 0);

  (void) printf("Encrypted message to be sent from server to client: \n");
  display_bytes(encrypted_server_answer, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + INTERNAL_MESSAGE_LENGTH);
}

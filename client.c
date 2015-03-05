/* Test program for crypto_box utilities 

   Michael Owusu
   Camila Mateo

   created February 25, 2015

*/

#include <stdio.h>
#include <assert.h>
#include <crypto_box.h>
#include <time.h>
#include "server.h"

// Declaration of variables 
int result; /* assertion for cryptobox */
int place = 0; /* additional counter */
long long int counter; /* counter for assigning bytes to char arrays */

/* client generated keypair */
unsigned char client_pk[crypto_box_PUBLICKEYBYTES];
unsigned char client_sk[crypto_box_SECRETKEYBYTES];                 

/* client generated nonce N1 */
unsigned char nonce_n1[crypto_box_NONCEBYTES];

/* nonce N1 with concatenated ZEROBYTES 0s */
unsigned char n1_with_zerobytes[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES];

/* encrypted N1 and ZEROBYTES 0s concatenation */
unsigned char encrypted_n1[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES];

/* initial message to be sent to server */
unsigned char initial_message[crypto_box_NONCEBYTES + crypto_box_ZEROBYTES + crypto_box_PUBLICKEYBYTES];

/* variable to store decrypted message to server */
unsigned char decrypted_message_1[SIZE_OF_TIME_T + (crypto_box_NONCEBYTES * 2) + crypto_box_ZEROBYTES];

/* server generated nonce N2  extracted from first server response */
unsigned char nonce_n2[crypto_box_NONCEBYTES];

/* client generated nonce N3 */
unsigned char nonce_n3[crypto_box_NONCEBYTES];

/* message containing client's question and nonces N2 and N3 */
unsigned char client_question_message[crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH];

/* encrypted message containing client's question and nonce N2 and N3 */
unsigned char client_question_encrypted[crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH];

/* decrypted answer message from server */
unsigned char decrypted_server_answer[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + INTERNAL_MESSAGE_LENGTH];

/* decrypted nonce N3 returned by server */
unsigned char returned_nonce_n3[crypto_box_NONCEBYTES];

/* bytes containing decrypted answer text from server */
unsigned char decrypted_answer_text[INTERNAL_MESSAGE_LENGTH];

/* Union to store time value as time_t and an unsigned char of bytes */
union timestamp {
  time_t native; 
  unsigned char bytes[sizeof(time_t)];
};

/* store timestamp parsed from server message for authentification */
union timestamp server_time;

/* store client generated timestamp for authentification*/
union timestamp client_time;

/* Union to store messages as bytes and and char*  */
union message {
  char* native; 
  unsigned char bytes[INTERNAL_MESSAGE_LENGTH];
};

/* question to send to server */
union message question;

/* answer received from server  */
union message answer;




/* Begin client functions for interacting with system and server */


/* Function to establish communication with server by sending over nonce N1 and identifying client public key to the server */
void clientInitialCommunication () {

  /* construct keypairs for sender */
  result = crypto_box_keypair(client_pk, client_sk);
  assert(result == 0);

  /* print client key pair using display bytes */
  (void) printf("Client Public Key:\n");
  display_bytes(client_pk, crypto_box_PUBLICKEYBYTES);

  (void) printf("Client Secret Key:\n");
  display_bytes(client_sk, crypto_box_SECRETKEYBYTES);

  /* generate nonce N1 */
  randombytes(nonce_n1, crypto_box_NONCEBYTES);

  /* print nonce N1 */
  (void) printf("Client generated nonce 1:\n");
  display_bytes(nonce_n1, crypto_box_NONCEBYTES);

  /* create initial communication request by added crypto_box_ZEROBYTES number of 0s to beginning of message */
  for (counter = 0; counter < crypto_box_ZEROBYTES; counter++)
    n1_with_zerobytes[counter] = 0;

  /* add nonce N1 to message */
  for (counter = counter; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter++)
    n1_with_zerobytes[counter] = nonce_n1[place++];

  /* print nonce N1 with concatenated zeroes */
  (void) printf("Nonce 1 with ZEROBYTES number of 0s for encryption:\n");
  display_bytes(n1_with_zerobytes, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);

  /* Encrypt nonce N1 */
  result = crypto_box(encrypted_n1, n1_with_zerobytes, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES, nonce_n0, server_pk, client_sk);
  assert(result == 0);

  /* print encrypted nonce N1 */
  (void) printf("Encrypted nonce N1 with ZEROBYTES 0s:\n");
  display_bytes(encrypted_n1, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);

  /* concatenate encrypted nonce 1 and the client public key to send to server */
  for (counter = 0; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter++)
    initial_message[counter] = encrypted_n1[counter];

  place = 0; /* reset placeholder */

  for (counter = counter; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES; counter++)
    initial_message[counter] = client_pk[place++];

  /* print final initial communication request to be sent to server */
  (void) printf("Encrypted nonce, N1, and client public key concatenated to send to server:\n");
  display_bytes(initial_message, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES);

}



/* after initial communication, client asks a question
   decrypts message using server public key and nonce and N2
   compose message containing question, N2, N3 and encrypt
   using nonce N2
*/
void clientAskQuestion () {

  /* Decrypt nonce n1 using server public key and nonce N1 */
  result = crypto_box_open(decrypted_message_1, encrypted_server_message_1, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T, nonce_n1, server_pk, client_sk);
  assert(result == 0);

  (void) printf("Client decrypted message:\n");
  display_bytes(decrypted_message_1, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T);


  /* extract nonce N2 and timestamp from server's sent message */

  place = 0; /* reset placeholder */

  /* save bytes from nonce N2 in decrypted message in a new char array */
  for (counter = crypto_box_NONCEBYTES + crypto_box_ZEROBYTES; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2); counter++)
    nonce_n2[place++] = decrypted_message_1[counter];

  /* Display nonce N2 extracted from server message */
  (void) printf("Nonce N2 extracted from server response 1:\n");
  display_bytes(nonce_n2, crypto_box_NONCEBYTES);

  place = 0; /* reset placeholder */

  /* extract server's timestamp */
  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T; counter++)
    server_time.bytes[place++] = decrypted_message_1[counter];

  /* display extracted from time stamp in seconds*/
  (void) printf("Server time in seconds:\n");
  (void) printf("%ld\n\n", server_time.native); 

  /* generate client time for authentication */
  client_time.native = time(NULL);

  (void) printf("Client time in seconds:\n");
  (void) printf("%ld\n\n", client_time.native);

  /* compare timestamps to verify authentication */
  if ((client_time.native - server_time.native) > 90) {
    /* If times are more than 90 seconds apart, end program */
    (void) printf("Timestamp authentication unsuccessful!\n");
    return;
  }
  /* if time stamps are within range, continue program */
  else (void) printf("Timestamp authentication successful.\n\n");  

  /* generate nonce 3 to send to server*/ 
  randombytes(nonce_n3, crypto_box_NONCEBYTES);

  /* print nonce 3 */
  (void) printf("Client generated nonce 3:\n");
  display_bytes(nonce_n3, crypto_box_NONCEBYTES);

  /* initialize question for server */
  question.native = "What's up?";

  /* add zeroes to beginning of question containing message to be encrypted */
  for (counter = 0; counter < crypto_box_ZEROBYTES; counter++)
    client_question_message[counter] = 0;

  /* concatenate nonce N2 to message */
  for (counter = counter; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter++)
    client_question_message[counter] = nonce_n2[place++];

  place = 0; /* reset placeholder */

  /* concatenate nonce N3 to message */ 
  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2); counter++)
    client_question_message[counter] = nonce_n3[place++];

  place = 0; /* reset placeholder */

  /* concatenate question to the message */
  for (counter = counter; counter < crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH; counter++)
    client_question_message[counter] = question.bytes[place++];

  (void) printf("Message containing question to be sent from client to server: \n");
  display_bytes(client_question_message, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH);

  /* encrypt concatenation of nonce N2, nonce N3 and question */
  result = crypto_box(client_question_encrypted, client_question_message, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH, nonce_n2, server_pk, client_sk);  
  assert(result == 0);

  /* print encrypted message to be sent to server */
  (void) printf("Encrypted question to send to Server: \n");
  display_bytes(client_question_encrypted, crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH);
}

/* function to decrypt and read answer to question from server */
void clientReadAnswer() {

  /* decrypt message containing answer from server */
  result = crypto_box_open(decrypted_server_answer, encrypted_server_answer, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + INTERNAL_MESSAGE_LENGTH, nonce_n3, server_pk, client_sk);
  assert(result == 0);

  /* Display decrypted answer message from server */
  (void) printf("Decrypted message containing answer from server, received by client: \n");
  display_bytes(decrypted_server_answer, crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + INTERNAL_MESSAGE_LENGTH);
 
  place = 0; /* reset placeholder */

  /* save bytes containing nonce N3 returned from server */
  for (counter = crypto_box_ZEROBYTES; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES; counter++)
    returned_nonce_n3[place++] = decrypted_server_answer[counter];

  place = 0; /* reset placeholder */

  int cmp;
  
  /* as part of verification, compare nonce N3 from server to client generated nonce N3 */
  if (strcmp(returned_nonce_n3, nonce_n3) == 0){

    (void) printf("Nonce N3 verification successful!\n\n");

    /* if verification is successful save and print answer from client */

    /* save bytes containing answer from server */
    for (counter = counter; counter < crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + SIZE_OF_TIME_T; counter++)
      answer.bytes[place++] = decrypted_server_answer[counter];

    (void) printf("Answer sent by Server and received by Client in bytes:\n");
    display_bytes(answer.bytes, INTERNAL_MESSAGE_LENGTH);
 
    (void) printf("Answer received in plaintext: \n");
    (void) printf("%s\n\n", answer.native);
  }

  /* if verification is unsuccessful, print error message and exit function */
  else{ 
    (void) printf("Nonce N3 verification unsuccessful!\n\n");
    return;
  }
  
}

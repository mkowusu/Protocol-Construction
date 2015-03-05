/* Test program for crypto_box utilities

   Michael Owusu
   Camila Mateo

   created February 25, 2015
*/


/* Information in this header file contains data and functions that the server effectively sends
   to the system for interacting with the client. No data is revealed through header file that would
   compromise security of communication. 
*/

#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0
#define SIZE_OF_TIME_T           1


/* Encrypted and necessary message slots that are sent to client via headerfile */

/* make server public key available for initial communication possible by client */
unsigned char server_pk[crypto_box_PUBLICKEYBYTES];

/* create 0 nonce for initial communication from server */
unsigned char nonce_n0[crypto_box_NONCEBYTES];

/* first encrypted message from server containing timestamp, and nonces N1 and N2 */ 
unsigned char encrypted_server_message_1[crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + SIZE_OF_TIME_T];

/* encrypted message from server containing answer and nonce N3 */
unsigned char encrypted_server_answer[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + INTERNAL_MESSAGE_LENGTH];

void generateN0();
void serverGenerateKeyPair();
void serverInitialResponse();
void serverAnswerQuestion();

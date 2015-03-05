/* Test program for crypto_box utilities

   Michael Owusu
   Camila Mateo

   created February 25, 2015
*/


/* Information in this header file contains data and functions that the client effectively sends
   to the system for interacting with the server. No data is revealed through header file that would
   compromise security of communication. 
*/

#define INTERNAL_MESSAGE_LENGTH  45
#define MESSAGE_LENGTH           (crypto_box_ZEROBYTES + INTERNAL_MESSAGE_LENGTH)
#define NO_ERROR                 0
#define SIZE_OF_TIME_T           1

/* Encrypted message slots that are sent to server via headerfile */

/* Client encrypted initiating communication message */
unsigned char initial_message[crypto_box_ZEROBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];

/* Encrypted question containing message */
unsigned char client_question_encrypted[crypto_box_ZEROBYTES + (crypto_box_NONCEBYTES * 2) + INTERNAL_MESSAGE_LENGTH];

/* Client functions to be used by system in communicating with server */
void clientInitialCommunication();
void clientAskQuestion();
void clientReadAnswer();


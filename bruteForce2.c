/**
 * Course: CPEN 442
 * Author: Trevor Yu
 * Date: October 28, 2015
 *
 * Summary: Code to brute force a hashed password.
 * The password uses 76 different characters.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <pthread.h>

#define BILLION 1000000000L

const char *possibleChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=";
const char *hashedPwd = "8EC2703E314CE2D796D9A5A7F4C9D55523C66EA4";
const char *salt = "kx";
char computedHash[40];
char currentPwd[6];
unsigned char hash[SHA_DIGEST_LENGTH];
int allOptionsChecked = 0;

pthread_t producer, consumer;
pthread_cond_t condc, condp;
pthread_mutex_t pwdBufferMutex;
char pwdBuffer[1000][6]; // Circular buffer of passwords
int counter = 0;

/**
 * Get index of character in the possibleChars global constant.
 */
int getIndex( char c ) {
   int index = -1;
   const char *ptr = strchr( possibleChars, c );
   if( ptr ) {
      index = ptr - possibleChars;
   }
   return index;
}

/**
 * Generates a new password by incrementing the current password
 * by the next character in the possibleChars global constant.
 */
void incrementPwd( int index ) {
   char currentChar = currentPwd[index];
   int possibleCharsIndex = getIndex( currentChar );

   possibleCharsIndex++;

   if( possibleCharsIndex > strlen( possibleChars ) - 1 ) {
      currentPwd[index] = possibleChars[0];
      int nextIndex = index + 1;
      if( nextIndex > strlen( currentPwd ) - 1 ) {
         allOptionsChecked = 1;
         return;
      } else {
         incrementPwd( nextIndex );
      }
   } else {
      currentPwd[index] = possibleChars[possibleCharsIndex];
   }
}

/**
 * Prints out the value of the hash parameter
 */
void printHash( unsigned char hash[SHA_DIGEST_LENGTH] ) {
   int i = 0;
   for( i = 0; i < 20; i++ ) {
      printf( "%02x", hash[i] );
   }
   printf( "\n" );
}

/**
 * Stores the value of the hash parameter in the
 * computedHash global variable.
 */
void storeHash( unsigned char hash[SHA_DIGEST_LENGTH] ) {
   int i = 0;
   memset( &computedHash[0], 0, sizeof(computedHash) );
   char value[2];
   for( i = 0; i < 20; i++ ) {
      snprintf( value, sizeof(value) + 1, "%02x", hash[i] );
      strcat( computedHash, value );
   }
}

/**
 * Function for the producer thread.
 * Creates a bunch of possible passwords and puts them into a
 * circular buffer.
 */
void *producerFunc( void *arg ) {
   char fullPwd[8];

   while( 1 ) {
      // Wait until the consumer has finished emptying the buffer
      pthread_mutex_lock( &pwdBufferMutex );
      while( counter > 0 )
         pthread_cond_wait( &condp, &pwdBufferMutex );

      for( counter = 0; counter < 1000; counter++ ) {
         sprintf( fullPwd, "%s%s", salt, currentPwd );

         strncpy( pwdBuffer[counter], fullPwd, strlen(fullPwd) );

         incrementPwd( 0 );

         if( allOptionsChecked ) {
            pthread_cond_signal( &condc );
            pthread_mutex_unlock( &pwdBufferMutex );
            pthread_exit( NULL );
         }
      }
      pthread_cond_signal( &condc );
      pthread_mutex_unlock( &pwdBufferMutex );
   }
}

/**
 * Function for the consumer thread.
 * Grabs passwords from the circular buffer of passwords and
 * computes its SHA-1 hash value. It then checks to see if the
 * generated SHA-1 hash value is equal to the one we are looking
 * for.
 */
void *consumerFunc( void *arg ) {
   while( 1 ) {
      // Wait until the producer has filled the buffer
      pthread_mutex_lock( &pwdBufferMutex );
      while( counter < 1000 ) {
         pthread_cond_wait( &condc, &pwdBufferMutex );
         if( allOptionsChecked ) {
            pthread_exit( NULL );
         }
      }

      for( counter = 999; counter >= 0; counter-- ) {
         // Compute the SHA-1 hash value for the password
         SHA1( pwdBuffer[counter], strlen(pwdBuffer[counter]),
               hash );

         storeHash( hash );

         // Check if the password has been found
         if( strcasecmp( computedHash, hashedPwd ) == 0 ) {
            printf( "Password found!\n" );
            printf( "The salt is: %s\n", salt );
            printf( "The password is: %s\n", currentPwd );

            // Stop the producer thread and exit out of this thread
            pthread_cancel( producer );
            pthread_mutex_unlock( &pwdBufferMutex );
            pthread_exit( NULL );
         }
      }

      pthread_cond_signal( &condp );
      pthread_mutex_unlock( &pwdBufferMutex );
   }
}

/**
 * Brute force password cracker.
 * Currently uses the SHA-1 algorithm.
 */
int main( void ) {
   // Get the starting time.
   uint64_t diff;
   struct timespec start, end;
   clock_gettime(CLOCK_MONOTONIC, &start);

   sprintf( currentPwd, "aaaaaa" );

   pthread_mutex_init( &pwdBufferMutex, NULL );
   pthread_cond_init( &condc, NULL );
   pthread_cond_init( &condp, NULL );

   pthread_create( &producer, NULL, producerFunc, NULL );
   pthread_create( &consumer, NULL, consumerFunc, NULL );

   pthread_join( producer, NULL );
   pthread_join( consumer, NULL );

   // Get the ending time and calculate the total time of the
   // password cracker.
   clock_gettime(CLOCK_MONOTONIC, &end);
   diff = BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;

   printf( "Total Time: %llu nanoseconds\n", (long long unsigned int) diff );

   return 0;
}

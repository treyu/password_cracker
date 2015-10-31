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
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <pthread.h>

#define BILLION 1000000000L
#define NUM_POSS_CHARS 76
#define NUM_THREADS 19
#define PASS_LENGTH 4

struct thread_info {
   pthread_t thread_id;
   int thread_num;
};

const char *possibleChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=";
const char *hashedPwd = "8EC2703E314CE2D796D9A5A7F4C9D55523C66EA4";
//const char *hashedPwd = "81e4807da0f10e6348acfab1c24defe5e6d7fd9a"; // Waaahc
const char *salt = "kx";
char computedHash[NUM_THREADS][40 + 1];
char currentPwd[NUM_THREADS][PASS_LENGTH + 1];
char fullPwd[NUM_THREADS][PASS_LENGTH + 2 + 1];

unsigned char hash[NUM_THREADS][SHA_DIGEST_LENGTH + 1];
int allOptionsChecked[NUM_THREADS] = { 0 };

struct thread_info *tinfo;
pthread_mutex_t pwdBufferMutex;

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
void incrementPwd( int index, int threadNum ) {
   char currentChar = currentPwd[threadNum][index];
   int possibleCharsIndex = getIndex( currentChar );

   possibleCharsIndex++;

   if( possibleCharsIndex > strlen( possibleChars ) - 1 ) {
      currentPwd[threadNum][index] = possibleChars[0];
      int nextIndex = index + 1;

      // nextIndex + 1 to get the actual position starting at 1
      // strlen( currentPwd ) - 2 to get the every character except
      // the last 1 (for parallelizing)
      if( nextIndex + 1 > strlen( currentPwd[threadNum] ) - 1 ) {
         allOptionsChecked[threadNum] = 1;
         return;
      } else {
         incrementPwd( nextIndex, threadNum );
      }
   } else {
      currentPwd[threadNum][index] = possibleChars[possibleCharsIndex];
   }
   currentPwd[threadNum][PASS_LENGTH] = '\0';
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
void storeHash( unsigned char hashValue[SHA_DIGEST_LENGTH], int threadNum ) {
   int i = 0;
   memset( computedHash[threadNum], 0, SHA_DIGEST_LENGTH * 2 );
   for( i = 0; i < SHA_DIGEST_LENGTH; i++ ) {
      snprintf( (char *)&(computedHash[threadNum][i*2]), 3,
                "%02x", hashValue[i] );
   }
   computedHash[threadNum][SHA_DIGEST_LENGTH * 2] = '\0';
}

/**
 * Function to be called for the different threads that will run.
 */
void *threadFunc( void *arg ) {
   struct thread_info *tinfoThread = arg;
   int threadNum = tinfoThread->thread_num;

   while( 1 ) {
      // Wait until the consumer has finished emptying the buffer
      snprintf( fullPwd[threadNum], strlen(salt) + PASS_LENGTH + 1, "%s%s",
                salt, currentPwd[threadNum] );

      SHA1( fullPwd[threadNum], strlen(fullPwd[threadNum]),
            hash[threadNum] );

      storeHash( hash[threadNum], threadNum );

      //printf( "Pwd %s: %s\n", currentPwd[threadNum], computedHash[threadNum] );
      //printf( "Thread %d: %s\n", threadNum, currentPwd[threadNum] );

      // Check if the password has been found
      if( strcasecmp( computedHash[threadNum], hashedPwd ) == 0 ) {
         printf( "Password found!\n" );
         printf( "The salt is: %s\n", salt );
         printf( "The password is: %s\n", currentPwd[threadNum] );

         // Stop the other threads and exit out of this thread
         int i;
         for( i = 0; i < NUM_THREADS; i++ ) {
            if( i != threadNum ) {
               pthread_cancel( tinfo[i].thread_id );
            }
         }
         pthread_exit( NULL );
      }

      incrementPwd( 0, threadNum );

      if( allOptionsChecked[threadNum] ) {
         pthread_exit( NULL );
      }
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

   int i;
   //int j;
   int threadNum = 0;
   //for( i = 0; i < NUM_POSS_CHARS; i++ ) {
   for( i = 0; i < NUM_THREADS; i++ ) {
      //for( j = 0; j < NUM_POSS_CHARS; j++ ) {
         sprintf( currentPwd[threadNum], "aaaa" );
         currentPwd[threadNum][PASS_LENGTH - 1] = possibleChars[i];
         //currentPwd[threadNum][PASS_LENGTH - 2] = possibleChars[j];
         currentPwd[threadNum][PASS_LENGTH] = '\0';
         threadNum++;
      //}
   }

   tinfo = calloc( NUM_THREADS, sizeof(struct thread_info) );
   if( tinfo == NULL ) {
      printf( "calloc error\n" );
      return 0;
   }

   for( i = 0; i < NUM_THREADS; i++ ) {
      tinfo[i].thread_num = i;
      pthread_create( &tinfo[i].thread_id, NULL, &threadFunc, &tinfo[i] );
   }

   for( i = 0; i < NUM_THREADS; i++ ) {
      pthread_join( tinfo[i].thread_id, NULL );
   }

   for( i = NUM_THREADS; i < NUM_THREADS * 2; i++ ) {
      sprintf( currentPwd[threadNum], "aaaa" );
      currentPwd[threadNum][PASS_LENGTH - 1] = possibleChars[i];
      currentPwd[threadNum][PASS_LENGTH] = '\0';
      threadNum++;
   }

   for( i = 0; i < NUM_THREADS; i++ ) {
      tinfo[i].thread_num = i;
      pthread_create( &tinfo[i].thread_id, NULL, &threadFunc, &tinfo[i] );
   }

   for( i = 0; i < NUM_THREADS; i++ ) {
      pthread_join( tinfo[i].thread_id, NULL );
   }

   for( i = NUM_THREADS; i < NUM_THREADS * 4; i++ ) {
      sprintf( currentPwd[threadNum], "aaaa" );
      currentPwd[threadNum][PASS_LENGTH - 1] = possibleChars[i];
      currentPwd[threadNum][PASS_LENGTH] = '\0';
      threadNum++;
   }

   for( i = 0; i < NUM_THREADS; i++ ) {
      tinfo[i].thread_num = i;
      pthread_create( &tinfo[i].thread_id, NULL, &threadFunc, &tinfo[i] );
   }

   for( i = 0; i < NUM_THREADS; i++ ) {
      pthread_join( tinfo[i].thread_id, NULL );
   }

   for( i = NUM_THREADS; i < NUM_THREADS * 8; i++ ) {
      sprintf( currentPwd[threadNum], "aaaa" );
      currentPwd[threadNum][PASS_LENGTH - 1] = possibleChars[i];
      currentPwd[threadNum][PASS_LENGTH] = '\0';
      threadNum++;
   }

   for( i = 0; i < NUM_THREADS; i++ ) {
      tinfo[i].thread_num = i;
      pthread_create( &tinfo[i].thread_id, NULL, &threadFunc, &tinfo[i] );
   }

   for( i = 0; i < NUM_THREADS; i++ ) {
      pthread_join( tinfo[i].thread_id, NULL );
   }

   free( tinfo );

   // Get the ending time and calculate the total time of the
   // password cracker.
   clock_gettime(CLOCK_MONOTONIC, &end);
   diff = BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;

   printf( "Total Time: %llu nanoseconds\n", (long long unsigned int) diff );

   return 0;
}

/**
 * Course: CPEN 442
 * Author: Trevor Yu
 * Date: October 28, 2015
 *
 * Summary: Code to brute force a hashed password.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>

#define BILLION 1000000000L

const char *hashedPwd = "E4F548B2ADC79439E8084ED953D94B7BDCBE2BAC";
const char *salt = "Fb";
char computedHash[40];

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
 * Brute force password cracker.
 * Currently uses the SHA-1 algorithm.
 */
int main( void ) {
   int counter = 0;
   unsigned char hash[SHA_DIGEST_LENGTH];
   char currentPwd[4];

   uint64_t diff;
   struct timespec start, end;
   clock_gettime(CLOCK_MONOTONIC, &start);

   // Possible values are 4 digits long
   while( counter < 10000 ) {
      if( counter < 10 ) {
         sprintf( currentPwd, "%s000%d", salt, counter );
      } else if( counter < 100 ) {
         sprintf( currentPwd, "%s00%d", salt, counter );
      } else if( counter < 1000 ) {
         sprintf( currentPwd, "%s0%d", salt, counter );
      } else {
         sprintf( currentPwd, "%s%d", salt, counter );
      }

      // Compute the SHA-1 hash value for the password
      SHA1( currentPwd, strlen(currentPwd), hash );
      storeHash( hash );

      // Check if the password has been found
      if( strcasecmp( computedHash, hashedPwd ) == 0 ) {
         printf( "Password found!\n" );
         printf( "The password is: %s\n", currentPwd );
         break;
      }

      counter++;
   }

   clock_gettime(CLOCK_MONOTONIC, &end);
   diff = BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;

   printf( "Total Time: %llu nanoseconds\n", (long long unsigned int) diff );

   return 0;
}

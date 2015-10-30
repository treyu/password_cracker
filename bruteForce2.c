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

#define BILLION 1000000000L

const char *possibleChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=";
const char *hashedPwd = "8EC2703E314CE2D796D9A5A7F4C9D55523C66EA4";
const char *salt = "kx";
char computedHash[40];
char currentPwd[6];

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
      incrementPwd( nextIndex );
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
 * Brute force password cracker.
 * Currently uses the SHA-1 algorithm.
 */
int main( void ) {
   unsigned char hash[SHA_DIGEST_LENGTH];

   // Get the starting time.
   uint64_t diff;
   struct timespec start, end;
   clock_gettime(CLOCK_MONOTONIC, &start);

   char fullPwd[8];

   sprintf( currentPwd, "aaaaaa" );

   while( 1 ) {
      sprintf( fullPwd, "%s%s", salt, currentPwd );

      // Compute the SHA-1 hash value for the password
      SHA1( fullPwd, strlen(fullPwd), hash );
      storeHash( hash );

      // Check if the password has been found
      if( strcasecmp( computedHash, hashedPwd ) == 0 ) {
         printf( "Password found!\n" );
         printf( "The salt is: %s\n", salt );
         printf( "The password is: %s\n", currentPwd );
         break;
      }

      incrementPwd( 0 );
   }

   // Get the ending time and calculate the total time of the
   // password cracker.
   clock_gettime(CLOCK_MONOTONIC, &end);
   diff = BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;

   printf( "Total Time: %llu nanoseconds\n", (long long unsigned int) diff );

   return 0;
}

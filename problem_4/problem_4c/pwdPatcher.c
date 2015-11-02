/**
 * Author: Trevor Yu
 * Date: Nov. 1, 2015
 * 
 * Summary:
 * This program takes in a password (string) and computes its SHA-1 hash.
 * Once it has the hash, it inserts the hash at the specified location in
 * the program (a hardcoded offset value). This program is intended for
 * changing the password to a reverse engineering problem for a computer
 * security course at UBC (CPEN 442). This program was written very
 * hastily and will result in strange behaviours if used on a different
 * program than the one assigned to me.
 *
 * When using this program, the new password should not contain any space
 * characters because the original program sees the space character as a
 * delimiter. So nothing after the space would be considered part of the
 * password.
 *
 * Reference: http://www.idabook.com/chapter14/ida_patcher.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "pwdPatcher.h"

int main(int argc, char **argv) {
   FILE *input = NULL;
   unsigned int offset = 0x12806;

   sha1nfo s;
   char *newPwd = NULL;
   uint8_t *hash;
  
   int i;

   // Check if the right number of arguments are passed in. 
   if (argc < 5) {
       fprintf(stderr, "usage:\n\t%s -i <binary> -n <new password>\n",
               argv[0]);
       exit(0);
   }

   for (i = 1; i < argc; i += 2) {
      if (!strcmp(argv[i], "-i")) {
         if ((i + 1) < argc) {
         	fprintf(stderr, "Opening %s\n", argv[i+1]);
            input = fopen(argv[i+1], "rb+");
            if (input == NULL) {
               fprintf(stderr, "Failed to open input file %s\n", argv[i+1]);
               exit(0);
            }
         }
      }
      else if (!strcmp(argv[i], "-n")) {
         if ((i + 1) < argc) {
             newPwd = argv[i + 1];
         }
      }
      else {
         fprintf(stderr, "usage:\n\t%s -i <binary> -n <new password>\n",
                 argv[0]);
         exit(0);
      }
   }

   // Calculate the hash for the new password
   sha1_init(&s);
   sha1_write(&s, newPwd, strlen( newPwd ) );
   hash = sha1_result(&s);

   // Put the new hash into the program
   for (i=0; i<20; i++) {
      printf("%02x", hash[i]);
      fseek(input, offset, SEEK_SET);
      fputc(hash[i], input);

      offset++;
   }
   fclose(input);

   return 0;
}

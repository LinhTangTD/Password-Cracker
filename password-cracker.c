/**
 * \author Linh Tang & Yolanda Jiang
 * \date April 7, 2020
 * \name Password Cracker
 */

#define _GNU_SOURCE
#include <openssl/md5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include "password.h"

#define MAX_USERNAME_LENGTH 64
#define PASSWORD_LENGTH 6
#define ALPHABET 26
#define NUM_THREADS 4

int crack_single_password_helper(char str[PASSWORD_LENGTH + 1], uint8_t *input_hash, char *output);
int crack_single_password(uint8_t *input_hash, char *output);
int crack_password_list_helper(password_set_t *passwords, char c[PASSWORD_LENGTH + 1]);
void increment(int *flag, char *c, int *idx);
void *crack_password_list_helper_2(void *arg);
int crack_password_list(password_set_t *passwords);

/**
 * This struct is the root of the data structure that holds parameter to pass in each thread's function.
 */
typedef struct args
{
  char start[PASSWORD_LENGTH + 1];
  char end[PASSWORD_LENGTH + 1];
  password_set_t *password_set;
} args_t;

/**
 * Check if a given string of six lower-case alphabetic 
 * character matches with the given hash value.
 *
 * \param input_hash  An array of MD5_DIGEST_LENGTH bytes that holds the hash of a password
 * \param output      A pointer to memory with space for a six character password + '\0'
 * \returns           0 if matched. -1 otherwise.
 */
int crack_single_password_helper(char str[PASSWORD_LENGTH + 1], uint8_t *input_hash, char *output)
{
  // Convert character array to string literal
  char *candidate_passwd = charToString(PASSWORD_LENGTH, str);
  // Take our candidate password and hash it using MD5
  uint8_t candidate_hash[MD5_DIGEST_LENGTH];                                        //< This will hold the hash of the candidate password
  MD5((unsigned char *)candidate_passwd, strlen(candidate_passwd), candidate_hash); //< Do the hash

  // Now check if the hash of the candidate password matches the input hash
  if (memcmp(input_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0)
  {
    // Match! Copy the password to the output and return 0 (success)
    strncpy(output, candidate_passwd, PASSWORD_LENGTH + 1);
    return 0;
  }
  else // No match. Return -1 (failure)
    return -1;
}

/**
 * Find a six character lower-case alphabetic password that hashes
 * to the given hash value. There is 26^6 possible passwords, thus the 
 * function will call 6 nested loop to iterate through all possibilities
 *
 * \param input_hash  An array of MD5_DIGEST_LENGTH bytes that holds the hash of a password
 * \param output      A pointer to memory with space for a six character password + '\0'
 * \returns           0 if the password was cracked. -1 otherwise.
 */
int crack_single_password(uint8_t *input_hash, char *output)
{
  char c[7] = "aaaaaa"; // The first starting guess
  for (int i0 = 0; i0 < ALPHABET; i0++)
  {
    c[0] = i0 + 'a';
    for (int i1 = 0; i1 < ALPHABET; i1++)
    {
      c[1] = i1 + 'a';
      for (int i2 = 0; i2 < ALPHABET; i2++)
      {
        c[2] = i2 + 'a';
        for (int i3 = 0; i3 < ALPHABET; i3++)
        {
          c[3] = i3 + 'a';
          for (int i4 = 0; i4 < ALPHABET; i4++)
          {
            c[4] = i4 + 'a';
            for (int i5 = 0; i5 < ALPHABET; i5++)
            {
              c[5] = i5 + 'a';
              // check if each possible password is the actual password we are looking for
              int cracked = crack_single_password_helper(c, input_hash, output);
              if (cracked == 0)
                return cracked;
            }
          }
        }
      }
    }
  }
  return -1; // if failed to crack the password
}

int cracked_count = 0;                                   // number of passwords successfully cracked
pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER; // lock to protect critical section (cracked_count)

/**
 * Check if a given string c of six lower-case alphabetic 
 * character matches with any of hash values in the given password set.
 * \param password  A pointer to a set of passwords
 * \param c         A string contains a possible password
 * \returns         1 if matched, 0 otherwise.
 */
int crack_password_list_helper(password_set_t *passwords, char c[PASSWORD_LENGTH + 1])
{
  // Convert character array to string literal
  char *candidate_passwd = charToString(PASSWORD_LENGTH, c);

  // Take our candidate password and hash it using MD5
  uint8_t candidate_hash[MD5_DIGEST_LENGTH];                                        //< This will hold the hash of the candidate password
  MD5((unsigned char *)candidate_passwd, strlen(candidate_passwd), candidate_hash); //< Do the hash

  // Iterate through the passwords set
  password_t *current = passwords->head;
  while (current != NULL)
  {
    // Now check if the hash of the candidate password matches the input hash
    if (memcmp(&(current->password_hash), candidate_hash, MD5_DIGEST_LENGTH) == 0)
    {
      printf("%s %s\n", current->username, candidate_passwd);
      return 1;
    }
    current = current->next;
  }
  return 0;
}

/**
 * Increment a given character by 1, used as helper in a loop to go over all possibile password
 * \param flag  A point to the flag
 * \param c     A pointer to the character to be incremented
 * \param idx   A pointer to the variable that holds the current array index in each loop iteration
 * \returns 
 */
void increment(int *flag, char *c, int *idx)
{
  if (*flag == 0)
  {
    *idx = *c - 'a';
    *flag = 1;
  }
  *c = *idx + 'a';
}

/**
 * Helper function to crack_password_list, cracking password if it's in the 
 * range of arg->start and arg->end and update the cracked_count (global) variable.
 * \param arg A pointer to the arg struct
 * \returns   
 */
void *crack_password_list_helper_2(void *arg)
{
  args_t *input;
  input = (args_t *)arg;
  int total_password = passwordCounter(input->password_set);
  int flag[6] = {0};
  char c[PASSWORD_LENGTH + 1] = "aaaaaa";
  strcpy(c, input->start);

  for (int i0 = c[0] - 'a'; i0 < ALPHABET; i0++)
  {
    c[0] = i0 + 'a';
    for (int i1 = 0; i1 < ALPHABET; i1++)
    {
      increment(&flag[1], &c[1], &i1);
      for (int i2 = 0; i2 < ALPHABET; i2++)
      {
        increment(&flag[2], &c[2], &i2);
        for (int i3 = 0; i3 < ALPHABET; i3++)
        {
          increment(&flag[3], &c[3], &i3);
          for (int i4 = 0; i4 < ALPHABET; i4++)
          {
            increment(&flag[4], &c[4], &i4);
            for (int i5 = 0; i5 < ALPHABET; i5++)
            {
              if (strcmp(c, input->end) == 0)
                return NULL;
              if (cracked_count == total_password)
                return NULL;
              increment(&flag[5], &c[5], &i5);

              int rc = pthread_mutex_lock(&count_mutex);
              assert(rc == 0);
              cracked_count += crack_password_list_helper(input->password_set, c);
              pthread_mutex_unlock(&count_mutex);
            }
          }
        }
      }
    }
  }
  return NULL;
}

/**
 * Crack all of the passwords in a set of passwords. The function should print the username
 * and cracked password for each user listed in passwords, separated by a space character.
 * Complete this implementation for part B of the lab.
 *
 * \returns The number of passwords cracked in the list
 */
int crack_password_list(password_set_t *passwords)
{
  int rc = 0;
  pthread_t p[NUM_THREADS];
  args_t *args[NUM_THREADS];
  char begin[PASSWORD_LENGTH + 1] = "aaaaaa";
  char last[PASSWORD_LENGTH + 1] = "aaaaaa";

  for (int i = 0; i < NUM_THREADS; i++)
  {
    args[i] = malloc(sizeof(args_t));
    strcpy(args[i]->start, begin);
    strcpy(last, begin);

    if (i == 3)
      for (int j = 0; j < PASSWORD_LENGTH; j++)
        last[j] = begin[j] + 7;
    else
      for (int j = 0; j < PASSWORD_LENGTH; j++)
        last[j] = begin[j] + 6;

    strcpy(args[i]->end, last);
    strcpy(begin, args[i]->end);
    args[i]->password_set = passwords;
    rc = pthread_create(&p[i], NULL, crack_password_list_helper_2, (void *)args[i]);
    assert(rc == 0);
  }

  for (int i = 0; i < NUM_THREADS; i++)
  {
    rc = pthread_join(p[i], NULL);
    assert(rc == 0);
  }
  return cracked_count;
}

int main(int argc, char **argv)
{
  if (argc != 3)
  {
    print_usage(argv[0]);
    exit(1);
  }
  if (strcmp(argv[1], "single") == 0)
  {
    // The input MD5 hash is a string in hexadecimal. Convert it to bytes.
    uint8_t input_hash[MD5_DIGEST_LENGTH];
    if (md5_string_to_bytes(argv[2], input_hash))
    {
      fprintf(stderr, "Input has value %s is not a valid MD5 hash.\n", argv[2]);
      exit(1);
    }

    // Now call the crack_single_password function
    char result[7];
    if (crack_single_password(input_hash, result) == -1)
    {
      printf("No matching password found.\n");
    }
    else
    {
      printf("%s\n", result);
    }
  }
  else if (strcmp(argv[1], "list") == 0)
  {
    // Make and initialize a password set
    password_set_t passwords;
    init_password_set(&passwords);

    // Open the password file
    FILE *password_file = fopen(argv[2], "r");
    if (password_file == NULL)
    {
      perror("opening password file");
      exit(2);
    }

    int password_count = 0;

    // Read until we hit the end of the file
    while (!feof(password_file))
    {
      // Make space to hold the username
      char username[MAX_USERNAME_LENGTH];

      // Make space to hold the MD5 string
      char md5_string[MD5_DIGEST_LENGTH * 2 + 1];

      // Make space to hold the MD5 bytes
      uint8_t password_hash[MD5_DIGEST_LENGTH];

      // Try to read. The space in the format string is required to eat the newline
      if (fscanf(password_file, "%s %s ", username, md5_string) != 2)
      {
        fprintf(stderr, "Error reading password file: malformed line\n");
        exit(2);
      }

      // Convert the MD5 string to MD5 bytes in our new node
      if (md5_string_to_bytes(md5_string, password_hash) != 0)
      {
        fprintf(stderr, "Error reading MD5\n");
        exit(2);
      }
      // Add the password to the password set
      add_password(&passwords, username, password_hash);
      password_count++;
    }

    // Now run the password list cracker
    int cracked = crack_password_list(&passwords);

    printf("Cracked %d of %d passwords.\n", cracked, password_count);
  }
  else
  {
    print_usage(argv[0]);
    exit(1);
  }

  return 0;
}
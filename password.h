/**
 * \author Linh Tang & Yolanda Jiang
 * \date April 7, 2020
 * \name Password Cracker
 */

#ifndef __PASSWORD_H__
#define __PASSWORD_H__

#define _GNU_SOURCE
#include <openssl/md5.h>
#include <unistd.h>
#include <string.h>

#define MAX_USERNAME_LENGTH 64
#define PASSWORD_LENGTH 6
#define ALPHABET 26

/**
 * This struct is the root of the data structure that will hold users and hashed passwords.
 */
typedef struct password
{
  char username[MAX_USERNAME_LENGTH];
  uint8_t password_hash[MD5_DIGEST_LENGTH];
  struct password *next;
} password_t;

/**
 * This struct is the root of the data structure represents the set of passwords, holding 2 pointers to the begining and the last password in the set
 */
typedef struct password_set
{
  password_t *head;
  password_t *tail;
} password_set_t;


/**
 * Count the number of passwords in the set
 * 
 * \param password  A pointer to a set of password
 * \return          Number of passwords contained in the set
 */
int passwordCounter(password_set_t *passwords);

/**
 * Initialize a password set.
 *
 * \param passwords  A pointer to allocated memory that will hold a password set
 */
void init_password_set(password_set_t *passwords);

/**
 * Add a password to a password set
 *
 * \param passwords   A pointer to a password set initialized with the function above.
 * \param username    The name of the user being added. 
 * \param password_hash   An array of MD5_DIGEST_LENGTH bytes that holds the hash of this user's
 *                        password. 
 */
void add_password(password_set_t *passwords, char *username, uint8_t *password_hash);

/**
 * Convert a character array to string literal
 * \param n     Length of the array
 * \param str   An array of n character
 * \returns     A string literal of length n
 */
char *charToString(int n, char str[n + 1]);

/**
 * Convert a string representation of an MD5 hash to a sequence
 * of bytes. The input md5_string must be 32 characters long, and
 * the output buffer bytes must have room for MD5_DIGEST_LENGTH
 * bytes.
 *
 * \param md5_string  The md5 string representation
 * \param bytes       The destination buffer for the converted md5 hash
 * \returns           0 on success, -1 otherwise
 */
int md5_string_to_bytes(const char *md5_string, uint8_t *bytes);

void print_usage(const char *exec_name);

#endif
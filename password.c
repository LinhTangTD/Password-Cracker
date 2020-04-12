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
#include <assert.h>

#include "password.h"

/**
 * Count the number of passwords in the set
 * 
 * \param password  A pointer to a set of password
 * \return          Number of passwords contained in the set
 */
int passwordCounter(password_set_t *passwords)
{
    int counter = 0;
    password_t *current = passwords->head;
    while (current != NULL)
    {
        counter++;
        current = current->next;
    }
    return counter;
}

/**
 * Initialize a password set.
 *
 * \param passwords  A pointer to allocated memory that will hold a password set
 */
void init_password_set(password_set_t *passwords)
{
    passwords->head = NULL;
    passwords->tail = NULL;
}

/**
 * Add a password to a password set
 *
 * \param passwords   A pointer to a password set initialized with the function above.
 * \param username    The name of the user being added. 
 * \param password_hash   An array of MD5_DIGEST_LENGTH bytes that holds the hash of this user's
 *                        password. 
 */
void add_password(password_set_t *passwords, char *username, uint8_t *password_hash)
{
    password_t *newPS = malloc(sizeof(password_t));
    assert(newPS != NULL);
    strcpy(newPS->username, username);
    memcpy(&(newPS->password_hash), password_hash, MD5_DIGEST_LENGTH);
    newPS->next = NULL;

    if (passwords->head == NULL)
    {
        passwords->head = newPS;
        passwords->tail = newPS;
        newPS->next = NULL;
    }
    else
    {
        password_t *temp = passwords->head;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = newPS;
        passwords->tail = newPS;
        newPS->next = NULL;
    }
}

/**
 * Convert a character array to string literal
 * \param n     Length of the array
 * \param str   An array of n character
 * \returns     A string literal of length n
 */
char *charToString(int n, char str[n + 1])
{
    // Convert character array to string literal
    char *string; //< This variable holds the password we are trying
    string = malloc(n + 1);
    memset(&string[0], 0x00, n + 1);
    memcpy(&string[0], &str[0], n);
    return string;
}

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
int md5_string_to_bytes(const char *md5_string, uint8_t *bytes)
{
    // Check for a valid MD5 string
    if (strlen(md5_string) != 2 * MD5_DIGEST_LENGTH)
        return -1;

    // Start our "cursor" at the start of the string
    const char *pos = md5_string;

    // Loop until we've read enough bytes
    for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        // Read one byte (two characters)
        int rc = sscanf(pos, "%2hhx", &bytes[i]);
        if (rc != 1)
            return -1;

        // Move the "cursor" to the next hexadecimal byte
        pos += 2;
    }

    return 0;
}

void print_usage(const char *exec_name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s single <MD5 hash>\n", exec_name);
    fprintf(stderr, "  %s list <password file name>\n", exec_name);
}

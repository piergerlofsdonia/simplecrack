#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#define _GNU_SOURCE
#include <crypt.h>
#include <pthread.h>
#define N_THREADS 40

/*
 * Concurrent (multi-threaded) version of crypt_example.c, a wordlist-lookup password cracker for 
    UNIX systems. 
 * Checks an input password string against the password hash of an input username.
 * Hashes the input plain-text password using SHA512 (default) and compares this hash against  
    a SHA512 hash of each input from a list of ~1million common passwords (see:  danielmiessler /
    SecLists on github).  
 * Developed as a simple proof-of-concept based on the technique outlined in TJ O'Connor's 
    book "Violent Python" (see: src/python/unix_crack.py).
*/

// Struct required as thread instances can only be given a single argument. 
typedef struct { 
    char* plaintext;
    char* hash;
    char* comparative;
    char* salt;
    int thread_number; // Not really required anymore, only used to debug.
} data;

pthread_mutex_t access_mutex = PTHREAD_MUTEX_INITIALIZER;
bool cracked = false;

void getEntry(char *username, char* return_string, int buffer_size) {
    /*
     * Opens the /etc/shadow file and reads each line.
     * If a line has a prefix that matches the input username, store that in the 
        return_string buffer.
     */
    int cmp_len = strlen(username);
    char* cmp_buff = malloc(cmp_len); // Buffer in which to store 'comparative' string.
	FILE *file_pointer; // Initalise file and line pointers.
	char *line_pointer = NULL;
	size_t buff_len = 0;

	file_pointer = fopen("/etc/shadow", "r"); // Read in password hashes.
	if ( file_pointer != NULL ) { // If the file_pointer is not set to a non-init value, an error occured.
        // Read a line of text from the file. 
		while(getline(&line_pointer, &buff_len, file_pointer) != -1) { // Read line-by-line until output is == -1.
            strncpy(cmp_buff, line_pointer, cmp_len); // Copy first n bytes into comparative.
            if ( strncmp(cmp_buff, username, cmp_len) == 0 ) { // If they match ... 
                strncpy(return_string, line_pointer+cmp_len+1, buffer_size-1); // Copy entire line to input buff.
            }
        }
    } else {
        printf("Could not read file!\n");
        exit(NULL); // Exit and notify the user.
	}
    
    return_string[buffer_size-1] = "\0"; // Add terminating byte.
    fclose(file_pointer);
    free(line_pointer); // Unallocate memory.
    return 0;
}

void parseHashString(char* hash, char* salt, int salt_len) {
    /*
     * Parse the input hashed password file string.
     * /etc/shadow hashes are segmented with '$' and ':'. There's no use for the password reset limit and time values,
        so we're electing to discard them. The "hash code" (a single digit detailing which cryptographic method was used) 
        and salt string are split from the initial string and stored into the same buffer in their original format '$<hashcode>$<salt>.
     */
	
    int i = 0;
    int hash_len = strlen(hash);
    bool split_found = false;

    for ( i; i < hash_len; i++ ) {
        if ( (int)hash[i] == 58 ) { // Check for ASCII code == 58 (:).
            split_found = true; // Colon detected at index 'i'.
            break; // Stop for loop (a little messy, I know).
        }
    }
    // Note: This might not need to be a conditional, as this split will always happen if the hash is valid.
    if ( split_found ) {  
        hash[i] = '\0'; // Escape the hash string at index 'i'.
        strncpy(salt, hash, salt_len); // Copy 'salt' portion of the hash into the associated buffer.
        salt[salt_len-1] = '\0'; // Add escape for salt buffer.
        memmove(hash, hash+(salt_len), (i-salt_len)); // Remove salt from hash string.
        hash[(i-salt_len)] = '\0'; // Re-add escape character in new position of index 'i'. 
    } else {
        printf("Cannot find split in hashed password!"); 
        exit(NULL);
    }
    return 0;
}

char *encryptString(char* plaintext_password, char* salt) {
    /*
     * Use GNULib 'crypt' - that is crypt(3) - to hash an input plain-text password.
     * Remove trailing and leading chars that are not required: e.g. the $<hashcode>$<salt>$ and the 
        trailing time values. 
     */
    char *hashed_password = crypt(plaintext_password, salt); // Hashed pass + hash code and salt.
    int salt_len = strlen(salt);
    int pass_len = strlen(hashed_password);
    
    if ( pass_len > salt_len ) { // If, for some reason, the string is not encrypted, return the salt string only.
        memmove(hashed_password, hashed_password+(salt_len+1), (pass_len-salt_len)); // Strip h.c. and salt. 
        hashed_password[pass_len-salt_len] = '\0'; // Add null byte.
    } else {
        hashed_password = salt;
        hashed_password[salt_len] = '\0';
    }
    return hashed_password;
}

void *checkHashes(void* args) {
    int comp_check;
    data *thread_params = args;
    int comparative_length = strlen(thread_params->comparative);
    thread_params->hash = encryptString(thread_params->plaintext, thread_params->salt);
    char *hash = thread_params->hash;
   
    if ( strcmp(hash, thread_params->comparative) == 0 ) {
        printf("Match: %s\n", thread_params->plaintext);
        cracked = true;

    } else {
        printf("No match found: %s\n", thread_params->plaintext);
    }

    free(thread_params);
    return 0;
}

void crackPassword(char* salt, char* hash) {
    /*
     * Read in the wordlist from 'wordlist.txt', for each plain-text password load it into a buffer.
     * When the buffer is full (n elements = N_THREADS), create a thread for each entry. 
     * Await the threads then repeat the above process until the password is found.  
     */

    FILE *file_pointer;
    char *line_pointer = NULL;
    size_t buffer_size = 0;
    unsigned int line_length = 0;
    unsigned int max_line_length = 32; // UNIX systems have a 32-char limit on passwords.
    pthread_t threads[N_THREADS]; // Thread array.
    int responses[N_THREADS];
    file_pointer = fopen("wordlist.txt", "r");
    if ( file_pointer == NULL ) exit(NULL);

    int l = 0;
    char *line_buffer[N_THREADS]; // String array.
    
    while(getline(&line_pointer, &buffer_size, file_pointer) != -1 ) {
        if ( ( l % N_THREADS == 0 ) && ( l != 0 ) ) { // If the buffer is full...

            pthread_mutex_init(&access_mutex, NULL); // Initalise mutex (this probably belongs in main()?).
            for ( int t = 0; t < N_THREADS; t++ ) { // Create each thread with the stored strings.
                data *thread_arguments = malloc(sizeof *thread_arguments);   
                thread_arguments->salt = salt;
                thread_arguments->comparative = hash;
                thread_arguments->thread_number = t;
                thread_arguments->plaintext = line_buffer[t];
                responses[t] = pthread_create(&threads[t], NULL, checkHashes, thread_arguments);
                if ( responses[t] != 0 ) free(thread_arguments);
            }
            // TODO: Implement fix for edge-case issue where password is in the last remaining lines of wordlist.txt.
		
            for ( int t = 0 ; t < N_THREADS; t++ ) {
               if ( responses[t] == 0 ) {
                   pthread_join(threads[t], NULL); // Await thread, do this before starting to re-allocate and re-fill the buffer.
               }        
            }
                      
            l = (l % N_THREADS); // Reset line counter.
        } 

        if ( cracked ) { // If we've found the password, close the file and return - some additional cleanup here would be ideal.
            fclose(file_pointer);
            return 0;
        }

        // Fill the string buffer with the next line, stripped of it's trailing whitespace char.
        line_length = strlen(line_pointer);
        line_pointer[line_length-1] = '\0';
        line_buffer[l] = malloc(max_line_length);
        strncpy(line_buffer[l], line_pointer, line_length);
        line_buffer[l][line_length-1] = '\0';
        l++;     
    }
}

int main(int argc, char *argv[]) {    
    if ( argc < 2 ) { 
	    printf("Incorrect number of command-line arguments provided, please provide a username from /etc/shadow to crack\n"); 
	    exit(NULL);
    } 

    int arg_len = strlen(argv[1]); // Check input args then set username.
    static char username[33];
    strncpy(username, argv[1], arg_len);
    username[arg_len] = '\0';
    char hash[255];
    char salt[12];
    getEntry(username, hash, sizeof(hash)); // Get entry from /etc/shadow.
    parseHashString(hash, salt, sizeof(salt)); // Parse the hash string from above.
    crackPassword(salt, hash); // Crack it bro.
    
}

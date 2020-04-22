#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#define _GNU_SOURCE
#include <crypt.h>
#define indeces_size 4

/*
 * A simple password-cracker for UNIX systems. 
 * Checks an input password string against the password hash of an input username.
 * Hashes the input plain-text password using SHA512 (default) and compares this hash against  
    a SHA512 hash of each input from a list of ~1million common passwords (see:  danielmiessler /
    SecLists on github).  
 * Developed as a simple proof-of-concept based on the technique outlined in TJ O'Connor's 
    book "Violent Python" (see: src/python/unix_crack.py).
*/

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
            		if ( strcmp(cmp_buff, username) == 0 ) { // If they match ... 
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
    	return;
}

void parseHashString(char* hash, char* salt, int salt_len) {
    /*
     * Parse the input hashed password file string.
     * /etc/shadow hashes are segmented with '$' and ':'. There's no use for the password reset limit and time values,
        so we're electing to discard them. The "hash code" (a single digit detailing which cryptographic method was used) 
        and salt string are split from the initial string and stored into the same buffer in their original format '$<hashcode>$<salt>.
     */
	
    printf("Parsing hash string %s\n", hash); 
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
    return;
}

char *encrypt_string(char* plaintext_password, char* salt) {
    /*
     * Use GNULib 'crypt' - that is crypt(3) - to hash an input plain-text password.
     * Remove trailing and leading chars that are not required: e.g. the $<hashcode>$<salt>$ and the 
        trailing time values. 
     */
    char *hashed_password = crypt(plaintext_password, salt); // Hashed pass + hash code and salt.
    int salt_len = strlen(salt);
    int pass_len = strlen(hashed_password);
    memmove(hashed_password, hashed_password+(salt_len+1), pass_len-salt_len); // Strip h.c. and salt.
    hashed_password[pass_len-salt_len] = '\0'; // Add null byte.
    return hashed_password;
}

void *decrypt_string(char *cracked_buff, char *comp_hash, char *salt) {
    /*
     * Increment through src/wordlist.txt, hashing each entry and comparing it against an input hash.
        If the hashed entry and input hash match, return the entry in plain-text. 
     * Uses memcmp instead of strcmp because its more efficient ( I think... ).
     */
    FILE *file_pointer;
    char *line_pointer = NULL;
    size_t buff_size = 0; // Initalise vars for file-reading.
    int comp_len = strlen(comp_hash); 
    int line_len;
    char hash_c[255];
    strncpy(&hash_c[0], &comp_hash[0], comp_len); // Copy input hash into a new buffer to avoid overwriting anything.
    hash_c[comp_len] = '\0';
    
    file_pointer = fopen("wordlist.txt", "r"); // Read wordlist.txt.
    if ( file_pointer != NULL ) { 
        while( getline(&line_pointer, &buff_size, file_pointer) != -1 ) {
            line_len = strlen(line_pointer)-1; // Set line length to be decremented by one to strip trailing w.s.
            line_pointer[line_len] = '\0';
            char *hashed = encrypt_string(line_pointer, salt); // Hash the string.
            if ( memcmp(&hashed[0], &hash_c[0], comp_len) == 0 ) { // Compare strings.
                strncpy(cracked_buff, line_pointer, line_len+1); // If it matches, copy to output buffer.
                cracked_buff[line_len+1] = '\0'; // Add null byte. 
                return; 
            } else {
                printf("Not a match: %s\n", line_pointer); // Print non-matches
            }
         } 
    } else {
        printf("Cannot open wordlist!");
        exit(NULL);
    }
}

int main(int argc, char *argv[]) {    
    if ( argc != 2 ) { 
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
    printf("Hash to match: %s\n", hash); 
    char plaintext[255];
    decrypt_string(plaintext, hash, salt); // Run through hashed word-list entries.
    printf("Cracked: %s\n", plaintext); 
}

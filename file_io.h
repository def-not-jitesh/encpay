
#ifndef FILE_IO // for conditional compilation 
#define FILE_IO

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <stdlib.h>
// defining functions for handling input/output

/* checks if the file given is a binary file */
int fileIsBin(const char** filename); 
/*
 * will take the filename is input
 * returns 0 if file DOES HAVE '.bin' extension
 * returns 1 if file DOES NOT HAVE '.bin' extension 
 */

/* checks if the file exists */
int fileExists(const char** filename);
/* 
 * will take the filename as input
 * return 0 if file DOES exist 
 * return 1 if file DOES NOT exist 
 */

/* checks if the file is empty */
int fileNotEmpty(const char** filename);
/* 
 * will take the filename as input 
 * returns 0 if the file IS EMPTY (0 represents the length of the file)
 * return the length of the file if the file IS NOT EMPTY
 */

/* reads the content of .bin file into a buffer */
PBYTE readInBuffer(const char** filename, DWORD* bytesRead);
/* 
 * takes the filename as input 
 * returns the base address of allocated buffer and also the number of bytesRead
 */

/* writes encrypted payload into a .bin file */
BOOL writeEncPayload(PBYTE enc_buf, SIZE_T enc_buf_size, DWORD* bytes_written);
/* 
 * takes the base address of encrypted buffer and buffer size as input
 * will write the encrypted buffer into a file called 'encrypted_payload.bin'
 */

/* writes the xor decryption function to decry_func.c file */
BOOL writeXorDecryptionFunc();

/* writes the rc4 decryption function to decry_func.c file */
BOOL writeRc4DecryptionFunc();

#endif

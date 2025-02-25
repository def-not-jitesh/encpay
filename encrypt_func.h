
#ifndef ENCRYPT_FUNC // for conditional compilation
#define ENCRYPT_FUNC

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <time.h>

// defining encryption/obfuscation methods
void xorEncryption(
		PBYTE PayloadBuf, // pointer to payload (PBYTE and BYTE* mean the same thing)
		DWORD bPayloadSize, // payload size
		const char *key, // key using which xor encryption will be performed
		DWORD key_len // the length of the key 
); //for xor encryption on buffer

void rc4Encryption(
		PBYTE PayloadBuf, // pointer to payload 
		DWORD bPayloadSize, // payload size
		const char *key, // key array used for rc4 algorithm
		DWORD key_len // length of the key array
); //for rc4 encryption on buffer


char* generateIpv4(int a, int b, int c, int d);
BOOL paddBufferIpv4(PBYTE input_buf, DWORD input_buf_size, PBYTE* output_padded_buf, SIZE_T* output_padded_buf_size);
PBYTE ipv4Obfuscation(PBYTE payload_buf, DWORD payload_buf_size, PBYTE obfuscated_payload, DWORD obfuscated_payload_size); //for ipv4 obfuscation of buffer

char* generateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p);
BOOL paddBufferIpv6(PBYTE input_buf, DWORD input_buf_size, PBYTE* output_padded_buf, SIZE_T* output_padded_buf_size);
PBYTE ipv6Obfuscation(PBYTE payload_buf, DWORD payload_buf_size, PBYTE obfuscated_payload, DWORD obfuscated_payload_size); //for ipv6 obfuscation of buffer

#endif


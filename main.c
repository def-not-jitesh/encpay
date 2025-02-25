
#include <unistd.h>
#include "file_io.h"
#include "encrypt_func.h"
#include <getopt.h>

int main(int argc, char** argv) {
	
	int opt;
	const char *file_name;
	const char *method;
	
	// getting input from user
	while ( ( opt = getopt(argc, argv, "f:m:")) != -1 )  {
		switch (opt) {
			case 'f':
				file_name = optarg;

				// checking if shellcode input is valid 
				if ((fileIsBin(&file_name) == 1) || (fileExists(&file_name) == 1) || (fileNotEmpty(&file_name) == -1)) {
				 	fprintf(stderr, "please give a valid file\n");
				 	exit(1);
				} 
				break;

			case 'm':
				method = optarg; 

				//also i need to check for invalid method
				if ((method != "ipv4" && method != "ipv6" && method != "xor" && method != "rc4")) {
				 	fprintf(stderr, "please specify a valid encryption/obfuscation method\n");
				 	exit(0);
				}
				break;

			default:
				printf("usage: %s -f payload -m method\n", argv[0]);
				return 1;
		}

	}
	
	//read the file into buffer
	
	DWORD bytesRead;
	PBYTE pPayloadBuf = readInBuffer(&file_name, &bytesRead);
	if (pPayloadBuf == NULL) {
		exit(1);
	}

	printf("read %d bytes of shellcode\n", bytesRead);

	//perform the particular encryption/obfuscation method on the buffer
	
	if (strcmp(method, "xor") == 0) {
		// perform xor encryption
		const char *key = "R@nd0m$Tr0ngK3y#2025";
		DWORD key_len = strlen(key);

		xorEncryption(pPayloadBuf, bytesRead, key, key_len);

		DWORD bytesWritten = 0;
		BOOL bWriteToBinFile = writeEncPayload(pPayloadBuf, bytesRead, &bytesWritten);

		if (bWriteToBinFile == FALSE) {
			exit(1);
		}

		// writing decryption function to c file 
		BOOL bWriteToCFileXor = writeXorDecryptionFunc();	
		if (bWriteToCFileXor == FALSE) {
			exit(1);
		}
	}
	
	else if (strcmp(method, "rc4") == 0) {
		// perform rc4 encryption
	
		const char* key = "secret";
		DWORD key_len = strlen(key);

		rc4Encryption(pPayloadBuf, bytesRead, key, key_len);

		DWORD bytesWritten = 0;
		BOOL bWriteToFile = writeEncPayload(pPayloadBuf, bytesRead, &bytesWritten);

		if (bWriteToFile == FALSE) {
			exit(1);
		}

		// writing decryption function to a c file
		BOOL bWriteToCFileRc4 = writeRc4DecryptionFunc();
		if (bWriteToCFileRc4 == FALSE) {
			exit(1);
		}
	}

	else if (strcmp(method, "ipv4") == 0) {
		// perform ipv4 obfuscation

		PBYTE pObfuscatedPayload = NULL;
		SIZE_T sObfuscatedPayloadSize = 0;

		pObfuscatedPayload = ipv4Obfuscation(pPayloadBuf, bytesRead, pObfuscatedPayload, sObfuscatedPayloadSize);
		if (pObfuscatedPayload == NULL) {
			exit(1);
		}

		DWORD bytesWritten = 0;
		BOOL bWriteToFile = writeEncPayload(pObfuscatedPayload, sObfuscatedPayloadSize, &bytesWritten);

		if (bWriteToFile == FALSE) {
			exit(1);
		}
	}

	else if (strcmp(method, "ipv6") == 0) {
		// perform ipv4 obfuscation

		PBYTE pObfuscatedPayload = NULL;
		DWORD sObfuscatedPayloadSize = 0;

		pObfuscatedPayload = ipv6Obfuscation(pPayloadBuf, bytesRead, pObfuscatedPayload, sObfuscatedPayloadSize);
	
		if (pObfuscatedPayload == NULL) {
			exit(1);
		}
		
		DWORD bytesWritten = 0;
		BOOL bWriteToFile = writeEncPayload(pObfuscatedPayload, sObfuscatedPayloadSize, &bytesWritten);
		
		if (bWriteToFile == FALSE) {
			exit(1);
		}
	}

	else { 
		// this will never run because i already check for input using getopt() function 
		fprintf(stderr, "please enter a valid obfuscation\n");
		exit(1);
	}

	return 0;
}


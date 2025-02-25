
// this file implements code to handle input/output

#include "file_io.h"

int fileIsBin(const char** filename) {
	const char* needle = ".";

	const char* result = strstr(*filename, needle); // this will make result point to '.' in the filename
	if (result == NULL) { 
		// checking if '.' exists in the filename
		fprintf(stderr, "you are supposed to give the payload in a .bin file (%lu)\n", GetLastError());
		return 1;
	} else {
		if (strcmp(result, ".bin") == 0) { // checking if the file has '.bin' extension
			printf("file does have a .bin extension\n");
			return 0;
		} else {
			fprintf(stderr, "file does not have a .bin extension (%lu)\n", GetLastError());
			return 1;
		}
	}
} 

int fileExists(const char** filename) {
	FILE *file = fopen(*filename, "r");
	if (file == NULL) {
		fprintf(stderr, "file does not exist, or you do not have read permissions to the file (%lu)\n", GetLastError());
		return 1;
	} else {
		fclose(file);
		return 0;
	}
}

int fileNotEmpty(const char** filename) {

	int length = 0;

	FILE *file = fopen(*filename, "r");
	if (file == NULL) {
		fprintf(stderr, "error in opening file\n");
		return -1;
	}

	int ch = fgetc(file);
	if (ch == EOF) {
		fprintf(stderr, "file is empty\n");
		return length;
	} else {
		while (ch != EOF) {
			length++;
			ch = fgetc(file);
		}
	}
	
	fclose(file);
	return length;
}

PBYTE readInBuffer(const char** filename, DWORD* bytesRead) {

	// we could have used OpenFile() but windows recommends CreateFile() now since, OpenFile() has deprecated
	HANDLE hFile = CreateFile(
			*filename, // the name of the file to open
			GENERIC_READ, // the permissions with which we want to open the file, in this case read permission
			0, 
			NULL, 
			OPEN_EXISTING, // open only if the file exists
			FILE_ATTRIBUTE_NORMAL,
			NULL
	);
	// checking if file handle is invalid
	if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "error opening file (%lu)\n", GetLastError());
		return NULL;
	}
	
	// function to get the size of the file
	DWORD file_size = GetFileSize(
			hFile, // handle to the file we want to open
			NULL
	);
	if (file_size == INVALID_FILE_SIZE) {
		fprintf(stderr, "failed to get the size of the file (%lu)\n", GetLastError());
		CloseHandle(hFile);
		return NULL;
	}
	*bytesRead = file_size;

	HANDLE hHeap = GetProcessHeap(); //gets the handle for the heap of current process
	if (hHeap == NULL) {
		fprintf(stderr, "failed to get handle of heap (%lu)\n", GetLastError());
		CloseHandle(hFile);
		return NULL;
	}
	
	//allocating buffer to read payload to from the file
	BYTE* pPayloadBuf = (BYTE*)HeapAlloc(
			hHeap, // handle of the heap memory for current process
			HEAP_ZERO_MEMORY, // will zero out the memory 
			file_size // the number of bytes to allocate
	);
	if (pPayloadBuf == NULL) {
		fprintf(stderr, "memory allocation has failed (%lu)\n", GetLastError());
		CloseHandle(hFile);
		return NULL;
	}
	
	// ReadFile() will read the contents of particular file into buffer
	if (!ReadFile(hFile, pPayloadBuf, file_size, bytesRead, NULL)) {
		fprintf(stderr, "failed to read from file into buffer (%lu)\n", GetLastError());
		CloseHandle(hFile);
		return NULL;
	}
	
	CloseHandle(hFile);

	return pPayloadBuf;
}

BOOL writeEncPayload(PBYTE enc_buf, SIZE_T enc_buf_size, DWORD* bytes_written) {

	HANDLE henc_pay_file = CreateFile(
				"encrypted_payload.bin", // name of the file to be created
				GENERIC_WRITE, // write permissions
				0, 
				NULL,
				CREATE_NEW, // will always create a new file, meaning file should not exist
				FILE_ATTRIBUTE_NORMAL,
				NULL
	);
	if (henc_pay_file == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "cannot create encrypted_payload.bin (%d)\n", GetLastError());
		return FALSE;
	}

	if (!WriteFile(henc_pay_file, enc_buf, enc_buf_size, bytes_written, NULL)) {
		fprintf(stderr, "cannot write to encrypted_payload.bin (%d)\n", GetLastError());
		CloseHandle(henc_pay_file);
		return FALSE;
	}

	if (!HeapFree(GetProcessHeap(), 0, enc_buf)) {
		fprintf(stderr, "failed to free memory for encrypted buffer (%d)\n", GetLastError());
		CloseHandle(henc_pay_file);
		return FALSE;
	}

	CloseHandle(henc_pay_file);

	return TRUE;
}

BOOL writeXorDecryptionFunc() {

	HANDLE hdecryptxor_c_file = CreateFile(
				"decrypt_xor.c", // name of the file to be created
				GENERIC_WRITE, // write permissions
				0, 
				NULL,
				CREATE_NEW, // will always create a new file, meaning file should not exist
				FILE_ATTRIBUTE_NORMAL,
				NULL
	);

	if (hdecryptxor_c_file == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "cannot create decrypt_func.c file (%d)\n", GetLastError());
		return FALSE;
	}

	const char *xor_decrypt = 
		"void xor_encryption(PBYTE pPayloadBuf, DWORD bPayloadSize, const char *key, DWORD key_len) {\n\tfor (DWORD i = 0; i < bPayloadSize; i++) {\n\t\tpPayloadBuf[i] = pPayloadBuf[i] ^ key[i % key_len];\n\t}\n}\n\nconst char *key = \"R@nd0m$Tr0ngK3y#2025\";\n";

	DWORD bytesWrittenXor;	
	if (!WriteFile(hdecryptxor_c_file, xor_decrypt, (DWORD)strlen(xor_decrypt), &bytesWrittenXor, NULL)) {
		fprintf(stderr, "cannot write to encrypted_payload.bin (%d)\n", GetLastError());
		CloseHandle(hdecryptxor_c_file);
		return FALSE;
	}

	CloseHandle(hdecryptxor_c_file);

	return TRUE;
}

BOOL writeRc4DecryptionFunc() {
	HANDLE hdecryptrc4_c_file = CreateFile(
				"decrypt_rc4.c", // name of the file to be created
				GENERIC_WRITE, // write permissions
				0, 
				NULL,
				CREATE_NEW, // will always create a new file, meaning file should not exist
				FILE_ATTRIBUTE_NORMAL,
				NULL
	);

	if (hdecryptrc4_c_file == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "cannot create file (%lu)\n", GetLastError());
		return FALSE;
	}

	const char *rc4_decrypt = 
		"void rc4_encryption(PBYTE PayloadBuf, DWORD bPayloadSize, const char *key, DWORD key_len) {\n\tDWORD S[256];\n\tfor (DWORD i = 0; i < 256; i++) {\n\t\tS[i] = i;\n\t}\n\n\tDWORD j = 0;\n\tfor (DWORD i=0; i < 256; i++) {\n\t\tj = (j + S[i] + key[i % key_len]) % 256;\n\t\tDWORD temp = S[i];\n\t\tS[i] = S[j];\n\t\tS[j] = temp;\n\t}\n\n\tDWORD i = 0; j = 0;\n\tfor (DWORD itr = 0; itr < bPayloadSize; itr++) {\n\t\ti = (i + 1) % 256;\n\t\tj = (j + S[i]) % 256;\n\t\tDWORD temp = S[i];\n\t\tS[i] = S[j];\n\t\tS[j] = temp;\n\t\tBYTE K = S[(S[i] + S[j]) % 256];\n\t\tPayloadBuf[itr] = PayloadBuf[itr] ^ K;\n\t}\n}\n\nconst char *key = \"secret\";";

	DWORD bytesWrittenRc4;	
	if (!WriteFile(hdecryptrc4_c_file, rc4_decrypt, (DWORD)strlen(rc4_decrypt), &bytesWrittenRc4, NULL)) {
		fprintf(stderr, "cannot write to encrypted_payload.bin (%d)\n", GetLastError());
		CloseHandle(hdecryptrc4_c_file);
		return FALSE;
	}

	CloseHandle(hdecryptrc4_c_file);

	return TRUE;
}



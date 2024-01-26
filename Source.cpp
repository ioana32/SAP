#include <stdio.h>
#include <malloc.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#define MESSAGE_CHUNK 512 
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)
#include <openssl/applink.c>
#include<string.h>

int main(int argc, char** argv)
{
	FILE* f = NULL;
	errno_t err;
	SHA256_CTX ctx;

	unsigned char finalDigest[SHA_DIGEST_LENGTH];
	SHA256_Init(&ctx);

	unsigned char* fileBuffer = NULL;
	unsigned char* fileBufferKey = NULL;
	unsigned char* fileBufferIV = NULL;
	err = fopen_s(&f, "name.txt", "r");
	if (err == 0) {
		//SHA256
		fseek(f, 0, SEEK_END);
		int fileLen = ftell(f);
		fseek(f, 0, SEEK_SET);

		fileBuffer = (unsigned char*)malloc(fileLen);
		fread(fileBuffer, fileLen, 1, f);
		unsigned char* tmpBuffer = fileBuffer;

		while (fileLen > 0) {
			if (fileLen > MESSAGE_CHUNK) {
				SHA256_Update(&ctx, tmpBuffer, MESSAGE_CHUNK);
			}
			else {
				SHA256_Update(&ctx, tmpBuffer, fileLen);
			}
			fileLen -= MESSAGE_CHUNK;
			tmpBuffer += MESSAGE_CHUNK;
		}

		SHA256_Final(finalDigest, &ctx);

		int count = 0;
		printf("\nSHA256 = ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
			printf("%02X ", finalDigest[i]);
			printf(" ");
		}
		printf("\n\n");

		//AES-256
		FILE* fkey = NULL;
		err = fopen_s(&fkey, "key.sec", "rb");

		FILE* fIV = NULL;
		errno_t errIV;
		errIV = fopen_s(&fIV, "iv.txt", "rb");
		if (err == 0 && errIV ==0) {
			fseek(fkey, 0, SEEK_END);
			int fileLenKey = ftell(fkey);
			fseek(fkey, 0, SEEK_SET);

			fileBufferKey = (unsigned char*)malloc(fileLenKey);
			fread(fileBufferKey, fileLenKey, 1, f);

			fseek(fIV, 0, SEEK_END);
			int fileLenIV = ftell(fIV);
			fseek(fIV, 0, SEEK_SET);

			fileBufferIV = (unsigned char*)malloc(fileLenIV);
			fread(fileBufferIV, fileLenIV, 1, f);

			unsigned char ciphertext[48];
			AES_KEY aes_key;
			AES_set_encrypt_key(fileBufferKey, (sizeof(fileBufferKey) * 8), &aes_key);
			AES_cbc_encrypt(fileBuffer, ciphertext, sizeof(ciphertext), &aes_key, fileBufferIV, AES_ENCRYPT);


			printf("Ciphertext for AES-CBC: ");
			for (unsigned int i = 0; i < sizeof(ciphertext); i++)
				printf("%02X", ciphertext[i]);

		}
		fclose(f);
		fclose(fkey);
		fclose(fIV);
	}

	return 0;
}

#include <stdio.h>
#include <malloc.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)
#include <openssl/applink.c>
#include<string.h>

//print the final result
void printFinal(unsigned char* text, const char* algOp, int length) {
	printf("\n%s = ", algOp);
	for (unsigned int i = 0; i < length; i++)
		printf("%02X", text[i]);
	printf("\n\n");
}

//print the final result
void printFinalInChar(unsigned char* text, const char* algOp, int length) {
	printf("\n%s = ", algOp);
	for (unsigned int i = 0; i < length; i++)
		printf("%c", text[i]);
	printf("\n\n");
}
// Function to print RSA public key details
void printRSAPublicKey(RSA* rsa) {
	if (rsa == NULL) {
		fprintf(stderr, "Invalid RSA public key\n");
		return;
	}

	// Get the public key components
	const BIGNUM* n = NULL;
	const BIGNUM* e = NULL;
	RSA_get0_key(rsa, &n, &e, NULL);

	// Print modulus (n) and public exponent (e)
	printf("Modulus (n): ");
	BN_print_fp(stdout, n);
	printf("\nPublic Exponent (e): ");
	BN_print_fp(stdout, e);
	printf("\n");
}
int main(int argc, char** argv)
{

	FILE* fsig = NULL;
	RSA* apub;
	FILE* f=NULL;
	unsigned char* buf = NULL;
	unsigned char* last_data = NULL;

	errno_t err1, err2;
	err1=fopen_s(&fsig,"key.sec", "rb");
	err2=fopen_s(&f,"pubISM.pem", "r");
	if (err1 == 0 && err2 == 0) {
		apub = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
		//printRSAPublicKey(apub);
		fclose(f);
		//printf("1");
		//printf("%d",RSA_size(apub));
		buf = (unsigned char*)malloc(RSA_size(apub));

		// there is one single ciphertext block
		fread(buf, RSA_size(apub), 1, fsig);
		last_data = (unsigned char*)malloc(SHA256_DIGEST_LENGTH); // 32 is the length of the SHA-256 algo result

		// decryption of the e-sign performed with the RSA public key
		RSA_public_decrypt(RSA_size(apub), buf, last_data, apub, RSA_PKCS1_PADDING);
		
		fclose(fsig);

		printf("\n SHA-256 content decrypted from digital signature file: ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02X ", last_data[i]);
		printf("\n");

		//AES
		unsigned char IV_dec[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		
		FILE* fmsg = NULL;
		err1 = fopen_s(&fmsg, "msg.enc", "rb");
		if (err1 == 0) {

			unsigned char restoringtext[48];
			AES_KEY aes_key;
			unsigned char key[32];
			memcpy(key, last_data, sizeof(key));
			printf("\n KEY: ");
			for (int i = 0; i < sizeof(key); i++)
				printf("%02X ", key[i]);
			printf("\n");
			AES_set_decrypt_key(key, (sizeof(key)*8), &aes_key);
			fseek(fmsg, 0, SEEK_END);
			int fileLen = ftell(fmsg);
			fseek(fmsg, 0, SEEK_SET);
			unsigned char* fileBuffer = NULL;
			fileBuffer = (unsigned char*)malloc(fileLen);
			fread(fileBuffer, fileLen, 1, fmsg);
			printf("file   ");
			for (unsigned int i = 0; i < sizeof(fileBuffer); i++)
				printf("%02X", fileBuffer[i]);
			//AES_cbc_encrypt(fileBuffer, restoringtext, sizeof(restoringtext), &aes_key, IV_dec, AES_DECRYPT);
			AES_cbc_encrypt(fileBuffer, restoringtext, sizeof(restoringtext), &aes_key, IV_dec, AES_DECRYPT);

			printf("\nRestored plaintext for AES-ECB: ");
			for (unsigned int i = 0; i < sizeof(restoringtext); i++)
				printf("%02X", restoringtext[i]);
			free(buf);
			free(last_data);
			free(fileBuffer);
			fclose(fmsg);
		}
		else {
			printf("File with message doesn't exist\n");
		}

	}
	else
		printf("Files don't exist\n");

	return 0;
}
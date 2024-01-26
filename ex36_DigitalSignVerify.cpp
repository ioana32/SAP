#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

int main(int argc, char** argv)
{
	if (argc == 3) {
		FILE* fsrc = NULL;
		FILE* fsig = NULL;
		errno_t err;
		SHA256_CTX ctx;

		// Step #1 Compute the message digest for the restored plaintext
		unsigned char finalDigest[SHA256_DIGEST_LENGTH];
		unsigned char* fileBuffer = NULL;
		SHA256_Init(&ctx);

		err = fopen_s(&fsrc, argv[1], "rb");
		fseek(fsrc, 0, SEEK_END);
		int fileLen = ftell(fsrc);
		fseek(fsrc, 0, SEEK_SET);

		fileBuffer = (unsigned char*)malloc(fileLen);
		fread(fileBuffer, fileLen, 1, fsrc);
		unsigned char* tmpBuffer = fileBuffer;

		while (fileLen > 0) {
			if (fileLen > SHA256_DIGEST_LENGTH) {
				SHA256_Update(&ctx, tmpBuffer, SHA256_DIGEST_LENGTH);
			}
			else {
				SHA256_Update(&ctx, tmpBuffer, fileLen);
			}
			fileLen -= SHA256_DIGEST_LENGTH;
			tmpBuffer += SHA256_DIGEST_LENGTH;
		}

		SHA256_Final(finalDigest, &ctx);

		printf("\n SHA-256 content computed: ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02X ", finalDigest[i]);
		printf("\n");

		fclose(fsrc);

		// Step #2 Decrypt the content of e-signature and compare it with the message digest resulted from Stage #1
		err = fopen_s(&fsig, argv[2], "rb");

		RSA* apub;
		FILE* f;
		unsigned char* buf = NULL;
		unsigned char* last_data = NULL;

		apub = RSA_new();

		f = fopen("pubKeySender.pem", "r");
		apub = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
		fclose(f);

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

		if (memcmp(last_data, finalDigest, SHA256_DIGEST_LENGTH) == 0) // the two message digests are compared: computed vs. decrypted from e-sign
			printf("\n Signature OK!\n");
		else
			printf("\n Signature does not validate the message!\n");

		free(last_data);
		free(buf);

		RSA_free(apub);

	}
	else {
		printf("\n Usage mode: OpenSSLProj.exe fSrc.txt eSignFsrc.txt");
		return 1;
	}

	return 0;
}
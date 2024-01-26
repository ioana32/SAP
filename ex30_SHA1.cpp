#include <stdio.h>
#include <malloc.h>
#include <openssl/sha.h>

#define MESSAGE_CHUNK 256 

int main(int argc, char** argv)
{
	if (argc == 2) {

		FILE* f = NULL;
		errno_t err;
		SHA_CTX ctx;

		unsigned char finalDigest[SHA_DIGEST_LENGTH];
		SHA1_Init(&ctx);

		unsigned char* fileBuffer = NULL;

		err = fopen_s(&f, argv[1], "rb");
		if (err == 0) {
			fseek(f, 0, SEEK_END);
			int fileLen = ftell(f);
			fseek(f, 0, SEEK_SET);

			fileBuffer = (unsigned char*)malloc(fileLen);
			fread(fileBuffer, fileLen, 1, f);
			unsigned char* tmpBuffer = fileBuffer;

			while (fileLen > 0) {
				if (fileLen > MESSAGE_CHUNK) {
					SHA1_Update(&ctx, tmpBuffer, MESSAGE_CHUNK);
				}
				else {
					SHA1_Update(&ctx, tmpBuffer, fileLen);
				}
				fileLen -= MESSAGE_CHUNK;
				tmpBuffer += MESSAGE_CHUNK;
			}

			SHA1_Final(finalDigest, &ctx);

			int count = 0;
			printf("\nSHA1 = ");
			for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
				printf("%02X ", finalDigest[i]);
				printf(" ");
			}
			printf("\n\n");

			fclose(f);
		}

	}
	else {
		printf("\n Usage Mode: SHA1.exe fSrc.txt \n\n");
		return 1;
	}

	return 0;
}

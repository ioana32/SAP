
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <openssl/aes.h>

int main(int argc, char** argv)
{
	if (argc == 5) {
		FILE* fSrc = NULL, * fDst = NULL;

		char opt[3];
		char mode[7];
		strcpy(opt, argv[1]);
		strcpy(mode, argv[2]);

		AES_KEY akey;
		unsigned char* inBuf = NULL;
		unsigned char* outBuf;
		unsigned char ivec[16];
		unsigned char userSymmetricKey[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
											   0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
		unsigned char wrongSymmetricKey[16] = { 0x11, 0x11, 0xf2, 0xf3, 0xc4, 0x55, 0xa6, 0xa7, 
												0xa0, 0xa1, 0x92, 0x93, 0x94, 0x95, 0x56, 0x77 };

		if (strcmp(opt, "-e") == 0) {
			fopen_s(&fSrc, argv[3], "rb");
			fopen_s(&fDst, argv[4], "wb");
			fseek(fSrc, 0, SEEK_END);
			long int inLen = ftell(fSrc); // inLen - file size in bytes
			fseek(fSrc, 0, SEEK_SET);
			long int outLen = 0;
			if ((inLen % 16) == 0)
				outLen = inLen;
			else
				outLen = ((inLen / 16) * 16) + 16; // outLen - total size of the ciphertext after encryption

			inBuf = (unsigned char*)malloc(outLen); // inBuf - allocated at ouLen to avoid adressing outside the allocated area in heap
			outBuf = (unsigned char*)malloc(outLen);
			memset(inBuf, 0x00, outLen);
			fread(inBuf, inLen, 1, fSrc); // copy the file content into inBuf (inLen less outLen)

			AES_set_encrypt_key(userSymmetricKey, 128, &akey); // set AES key for encryption (128 bits)

			if (strcmp(mode, "-ecb") == 0) {
				for (int i = 0; i < (outLen / 16); i++)
					AES_encrypt(&(inBuf[i * 16]), &(outBuf[i * 16]), &akey); // AES-ECB encryption done block-by-block (AES block is 16 bytes)
			}
			else {
				memset(&ivec, 0x01, sizeof(ivec)); // set the content of the initialization vector (IV)
				AES_cbc_encrypt(inBuf, outBuf, outLen, &akey, ivec, AES_ENCRYPT); // AES-CBC encryption done in one sigle step for entire plaintext as input
			}

			fwrite(&inLen, sizeof(inLen), 1, fDst); // size of the plaintext is saved into encrypted file to know how many bytes to restore at decryption time
			fwrite(outBuf, outLen, 1, fDst); // ciphertext saved into file
			free(outBuf);
			free(inBuf);
			fclose(fDst);
			fclose(fSrc);
		}
		else {
			fopen_s(&fSrc, argv[3], "rb");
			fopen_s(&fDst, argv[4], "wb");
			fseek(fSrc, 0, SEEK_END);
			long int inLen = ftell(fSrc) - 4; // inLen - ciphertext length
			fseek(fSrc, 0, SEEK_SET);
			long int outLen = 0;
			fread(&outLen, sizeof(outLen), 1, fSrc); // outLen - size of the restored message read from the first 4 bytes of the ciphertext file

			inBuf = (unsigned char*)malloc(inLen);
			outBuf = (unsigned char*)malloc(inLen);
			memset(inBuf, 0x00, inLen);
			fread(inBuf, inLen, 1, fSrc); // inBuf - ciphertext content

			//AES_set_decrypt_key(wrongSymmetricKey, 128, &akey);
			AES_set_decrypt_key(userSymmetricKey, 128, &akey); // set the AES key for decryption; must be the same as the one used for encryption

			if (strcmp(mode, "-ecb") == 0) {
				for (int i = 0; i < (inLen / 16); i++)
					AES_decrypt(&(inBuf[i * 16]), &(outBuf[i * 16]), &akey); // AES-ECB decryption block-by-block
			}
			else {
				memset(&ivec, 0x02, sizeof(ivec));
				AES_cbc_encrypt(inBuf, outBuf, inLen, &akey, ivec, AES_DECRYPT); // AES-CBC decryption as oneshot operation
			}

			fwrite(outBuf, outLen, 1, fDst); // restored message saved into a file
			free(outBuf);
			free(inBuf);
			fclose(fDst);
			fclose(fSrc);
		}
	}
	else {
		printf("\n Usage Mode: OpenSSLProj.exe -e -cbc fSrc.txt fDst.txt");
		printf("\n Usage Mode: OpenSSLProj.exe -d -ecb fSrc.txt fDst.txt");
		return 1;
	}
	printf("\n Process done.");
	return 0;
}

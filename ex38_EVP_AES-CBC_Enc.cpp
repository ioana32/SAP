#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stdio.h>

// https://github.com/richmit/ex-OpenSSL/blob/master/evp_encrypt.c

#define INBUFSIZE 512
#define OUTBUFSIZE (512*512)

void prtErrAndExit(int eVal, char* msg);
int main(int argc, char* argv[]);

int main(int argc, char* argv[]) {
	int outBytes, inBytes, tmpOutBytes, bytesInBuf, i;
	int cipherBlockSize, cipherKeyLength, cipherIvLength;
	unsigned char key[] = { /* Need all 32 bytes... */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	unsigned char iv[] = { /* Only need 16 bytes... */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	unsigned char buf2crypt[INBUFSIZE];
	unsigned char outBuf[OUTBUFSIZE];
	EVP_CIPHER_CTX *ctx;

	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx); // allocation/initilization of the cipher context structure
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv); // specifies the actual cipher to be used in the implementation below

	cipherBlockSize = EVP_CIPHER_CTX_block_size(ctx);
	cipherKeyLength = EVP_CIPHER_CTX_key_length(ctx); // validate against the key input 
	cipherIvLength = EVP_CIPHER_CTX_iv_length(ctx);   // validate against the iv input 

	fprintf(stderr, "INFO(evp_encrypt): Enc Algo:   %s\n", OBJ_nid2ln(EVP_CIPHER_CTX_nid(ctx)));
	fprintf(stderr, "INFO(evp_encrypt): Key:        ");
	for (i = 0; i < cipherKeyLength; i++)
		fprintf(stderr, "%02X", (int)(key[i]));
	fprintf(stderr, "\n");
	fprintf(stderr, "INFO(evp_encrypt): IV:         ");
	for (i = 0; i < cipherIvLength; i++)
		fprintf(stderr, "%02X", (int)(iv[i]));
	fprintf(stderr, "\n");
	fprintf(stderr, "INFO(evp_encrypt): block size: %d\n", cipherBlockSize);
	fprintf(stderr, "INFO(evp_encrypt): key length: %d\n", cipherKeyLength);
	fprintf(stderr, "INFO(evp_encrypt): IV length:  %d\n", cipherIvLength);

	if ((cipherKeyLength > 32) || (cipherIvLength > 16))
		prtErrAndExit(1, (char*)"ERROR: Hardwired key or iv was too short!!\n");

	fprintf(stderr, "INFO(evp_encrypt): READING DATA -----> ");
	inBytes = outBytes = 0;
	//strcpy((char*)buf2crypt, "qwerty");
	//bytesInBuf = strlen((const char*)buf2crypt);
	while ((bytesInBuf = fread(buf2crypt, sizeof(char), INBUFSIZE, stdin)) > 0) {
		fprintf(stderr, ".");
		if ((OUTBUFSIZE - ((bytesInBuf + cipherBlockSize - 1) + outBytes)) <= 0)
			prtErrAndExit(1, (char*)"ERROR: Buffer was not big enough to hold encrypted data!!\n");
		//if (!EVP_EncryptUpdate(ctx, outBuf + outBytes, &tmpOutBytes, buf2crypt, bytesInBuf))
		if (!EVP_EncryptUpdate(ctx, outBuf + outBytes, &tmpOutBytes, buf2crypt, bytesInBuf - 1)) // apply encryption on buf2crypt; encrypted content added to outBuf + outBytes
			prtErrAndExit(1, (char*)"ERROR: EVP_EncryptUpdate didn't work...\n");
		outBytes += tmpOutBytes;
		//inBytes += bytesInBuf ;
		inBytes += bytesInBuf - 1;
	} /* end while */
	fprintf(stderr, "DONE\n");

	if ((OUTBUFSIZE - (cipherBlockSize + outBytes)) <= 0)
		prtErrAndExit(1, (char*)"ERROR: Buffer was not big enough to hold encrypted data!!\n");
	if (!EVP_EncryptFinal_ex(ctx, outBuf + outBytes, &tmpOutBytes)) // performs final operations over the buffers in order to conclude the encryption
		prtErrAndExit(1, (char*)"ERROR: EVP_EncryptFinal_ex didn't work...\n");
	outBytes += tmpOutBytes;

	fprintf(stderr, "INFO(evp_encrypt): Bytes in:   %d\n", inBytes);
	fprintf(stderr, "INFO(evp_encrypt): Bytes out:  %d\n", outBytes);

	EVP_CIPHER_CTX_cleanup(ctx); // release/deallocate internals for the cipher context ctx

	fwrite(outBuf, 1, outBytes, stdout); // write cryptotext as it is in internal buffer outBuf
	fprintf(stdout, "\n Encrypted: ");
	for (int i = 0; i < outBytes; i++)
		fprintf(stdout, "%02X ", outBuf[i]);

	FILE* fb, * ft;
	fb = fopen("str_bin.enc", "wb+"); // fisier cu continut binar
	ft = fopen("str_txt.enc", "w+"); // fisier cu continut de tip text (fiecare byte este cod ASCII)

	fwrite(outBuf, 1, outBytes, fb); // all content of outBuf copied into str_bin.enc

	fprintf(ft, "%d\n", inBytes);
	for (int i = 0; i < outBytes; i++)
		fprintf(ft, "%02X", outBuf[i]);

	fclose(fb);
	fclose(ft);

	return 1;
} /* end func main */

  /* Save some vertical space with this simple error handling function.. */
void prtErrAndExit(int eVal, char* msg) {
	if (msg != NULL)
		fprintf(stderr, "INFO(evp_encrypt): %s\n\n", msg);
	exit(eVal);
} /* end func prtErrAndExit */
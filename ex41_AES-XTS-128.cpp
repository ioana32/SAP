#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#include <string.h>

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
	unsigned char* iv, unsigned char* ciphertext)
{
	EVP_CIPHER_CTX* ctx;

	int len;
	//int i;
	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, NULL))
		handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 128 bit AES (i.e. a 128 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;
	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
	unsigned char* iv, unsigned char* plaintext)
{
	EVP_CIPHER_CTX* ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 128 bit AES (i.e. a 128 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

int main(void)
{
	/* Set up the key and iv
	 */

	// Input block aligned - IEEE P1619, Vector 7
	 /* A 128x2 bit key */
	unsigned char key[] = {
		0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45,
		0x23, 0x53, 0x60, 0x28, 0x74, 0x71, 0x35, 0x26,
		0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93,
		0x23, 0x84, 0x62, 0x64, 0x33, 0x83, 0x27, 0x95
	};

	/* A 128 bit IV */
	// right position for fd is byte 1!!!
	unsigned char iv[] = {
		0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	// Message to be encrypted
	unsigned char plaintext[] = {
		0x8e, 0x41, 0xb7, 0x8c, 0x39, 0x0b, 0x5a, 0xf9, 
	    0xd7, 0x58, 0xbb, 0x21, 0x4a, 0x67, 0xe9, 0xf6, 
	    0xbf, 0x77, 0x27, 0xb0, 0x9a, 0xc6, 0x12, 0x40, 
	    0x84, 0xc3, 0x76, 0x11, 0x39, 0x8f, 0xa4, 0x5d
	};

	////////////////////////////////////
	//// Input not block aligned - IEEE P1619, Vector 15
	// /* A 128x2 bit key */
	//unsigned char key[] = {
	//	0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 
	//	0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
	//	0xbf, 0xbe, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 
	//	0xb7, 0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1, 0xb0
	//};

	///* A 128 bit IV */
	//unsigned char iv[] = {
	//	0x9a, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00,
	//	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	//};

	///* Message to be encrypted */
	//unsigned char plaintext[] = {
	//	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
	//	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
	//	0x10
	//};

	/* Buffer for ciphertext. Ensure the buffer is long enough for the
	 * ciphertext which may be longer than the plaintext, dependant on the
	 * algorithm and mode
	 */
	unsigned char ciphertext[100];

	/* Buffer for the decrypted text */
	unsigned char decryptedtext[100];

	int decryptedtext_len, ciphertext_len;

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Encrypt the plaintext */
	ciphertext_len = encrypt(plaintext, sizeof(plaintext), key, iv, ciphertext);

	/* Do something useful with the ciphertext here */
	printf("Ciphertext is:\n");
	BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);

	/* Decrypt the ciphertext */
	decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

	/* Add a NULL terminator. We are expecting printable text */
	// decryptedtext[decryptedtext_len] = '\0';

	/* Show the decrypted text */
	printf("Decrypted text is:\n");
	BIO_dump_fp(stdout, (const char*)decryptedtext, decryptedtext_len);

	unsigned char not_equal = 0;
	for (unsigned char i = 0; i < decryptedtext_len; i++)
	{
		if (plaintext[i] != decryptedtext[i])
			not_equal = 1;
	}

	if (not_equal)
		printf("\n AES-XTS has failed!\n");

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}
#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int main(int argc, char** argv)
{
	if (argc == 4) {
		FILE* fsrc = NULL;
		FILE* fdst = NULL;
		FILE* frst = NULL;
		errno_t err;

		err = fopen_s(&fsrc, argv[1], "rb");
		fseek(fsrc, 0, SEEK_END);
		int fileLen = ftell(fsrc);
		fseek(fsrc, 0, SEEK_SET);


		RSA* apub;
		RSA* apriv;
		FILE* f;

		unsigned char* e_data = NULL;
		unsigned char* last_data = NULL;

		// apriv = RSA_new();
		// apub = RSA_new();

		// RSA encryption
		f = fopen("pubKeyReceiver.pem", "r");
		apub = PEM_read_RSAPublicKey(f, NULL, NULL, NULL); // load RSA public key components into RSA structure
		fclose(f);

		err = fopen_s(&fdst, argv[2], "wb");

		unsigned char* fsrcbuf = (unsigned char*)malloc(RSA_size(apub) + 1); // allocate buffer to store plaintext chunks, eack chunck has 128 bytes == RSA key length
		fsrcbuf[RSA_size(apub)] = 0x00;
		e_data = (unsigned char*)malloc(RSA_size(apub)); // allocate buffer to store the ciphertext on 128 bytes same like the RSA key length
		if (fileLen != RSA_size(apub)) {
			while (fread_s(fsrcbuf, RSA_size(apub), sizeof(unsigned char), RSA_size(apub), fsrc) == RSA_size(apub)) {
				// encryption block-by-block, each block has RSA key length (1024 bits)
				// because the block is filled in fully, then there is no padding to be used here
				RSA_public_encrypt(RSA_size(apub), fsrcbuf, e_data, apub, RSA_NO_PADDING); // if the plaintext is matching the number of blocks, 
																						   // the last full block will be encrypted without padding
				fwrite(e_data, sizeof(unsigned char), RSA_size(apub), fdst);
			}
		}
		else {
			fread_s(fsrcbuf, RSA_size(apub), sizeof(unsigned char), RSA_size(apub), fsrc);
		}

		if (fileLen % RSA_size(apub)) // if there are additional bytes to be encrypted
		{
			RSA_public_encrypt(fileLen % RSA_size(apub), fsrcbuf, e_data, apub, RSA_PKCS1_PADDING); // encryption of the last block with padding because it couls be a partial block (less 1024 bits)
			fwrite(e_data, sizeof(unsigned char), RSA_size(apub), fdst);
		}

		// RSA decryption
		f = fopen("privKeyReceiver.pem", "r");
		apriv = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL); // load RSA private key components into RSA openssl structure
		fclose(f);

		free(e_data);
		e_data = (unsigned char*)malloc(RSA_size(apub)); // buffer to store the inpur ciphertext block with 128 bytes 
		last_data = (unsigned char*)malloc(RSA_size(apub)); // buffer to store the restored block of the plaintext
		fclose(fdst);

		fopen_s(&fdst, argv[2], "rb");
		fseek(fdst, 0, SEEK_END);
		int fileLen2 = ftell(fdst);
		fseek(fdst, 0, SEEK_SET);

		int maxChunks = fileLen2 / RSA_size(apub); // number of ciphertext blocks
		int currentChunk = 1;

		err = fopen_s(&frst, argv[3], "wb");

		if (fileLen2 != RSA_size(apub)) {
			while (fread_s(e_data, RSA_size(apub), sizeof(unsigned char), RSA_size(apub), fdst) == RSA_size(apub)) {
				if (currentChunk != maxChunks) { // 1 to (maxChunks - 1) are considered here because no padding
					// decryption done block-by-block; each block must have 1024 bits as length
					// because each block is filled in fully, there is no padding to be added here
					RSA_private_decrypt(RSA_size(apub), e_data, last_data, apriv, RSA_NO_PADDING);
					fwrite(last_data, sizeof(unsigned char), RSA_size(apub), frst);
					currentChunk++;
				}
			}
		}
		else {
			fread_s(e_data, RSA_size(apub), sizeof(unsigned char), RSA_size(apub), fdst);
		}


		if (fileLen % RSA_size(apub))
		{
			// could be a partial block; the padding must be used to meet the length of RSA key
			RSA_private_decrypt(RSA_size(apub), e_data, last_data, apriv, RSA_PKCS1_PADDING);
			fwrite(last_data, sizeof(unsigned char), fileLen % RSA_size(apub), frst);
			//fwrite(last_data, sizeof(unsigned char), RSA_size(apub), frst); // write the restored/decrypted block together with the padding (PKCS1)
		}
		else
		{
			// the last block to decrypted is a full block in plaintext; no padding required for decryption
			RSA_private_decrypt(RSA_size(apub), e_data, last_data, apriv, RSA_NO_PADDING);
			fwrite(last_data, sizeof(unsigned char), RSA_size(apub), frst);
		}


		free(last_data);
		free(e_data);
		free(fsrcbuf);

		RSA_free(apub);
		RSA_free(apriv);

		fseek(frst, 0, SEEK_END);
		printf("Nr. of bytes on the decrypted file: %d \n", ftell(frst));
		fseek(fsrc, 0, SEEK_END);
		printf("Nr. of bytes on the input file: %d", ftell(fsrc));

		fclose(fsrc);
		fclose(frst);
		fclose(fdst);

	}
	else {
		printf("\n Usage mode: OpenSSLProj.exe f1.txt encryptf1.txt f9.txt");
		return 1;
	}

	return 0;
}
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
		FILE* fdst = NULL;
		errno_t err;
		SHA256_CTX ctx;

		unsigned char finalDigest[SHA256_DIGEST_LENGTH];
		SHA256_Init(&ctx);
		unsigned char* fileBuffer = NULL;

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
			  
		printf("SHA(256) = ");
		for( int i=0; i<SHA256_DIGEST_LENGTH; i++)
			printf( "%02X ", finalDigest[i] );        	
		printf("\n");
		  	
		fclose(fsrc);

		err = fopen_s(&fdst, argv[2], "wb");

		RSA* apriv;
		FILE* f;

		unsigned char* buf = NULL;
		unsigned char* e_data = NULL;
		unsigned char* last_data = NULL;

		//unsigned char finalDigest[] = {
		//	0x99, 0x92, 0x62, 0x83, 0xe5, 0xa5, 0x49, 0x80,
		//	0xf1, 0x28, 0xd8, 0x04, 0x24, 0x47, 0xef, 0x87,
		//	0xae, 0xb1, 0x39, 0xd5, 0x65, 0xd4, 0x90, 0xcd,
		//	0xbd, 0x65, 0x1f, 0xdf, 0xec, 0x67, 0xfc, 0xfc
		//};

		//unsigned char finalDigest[] = {  // MD5  
		//	0x06, 0x48, 0x2B, 0x1F, 0x3E, 0xD9, 0x61, 0x44, 
		//	0xFC, 0x9F, 0x83, 0x57, 0x1E, 0xCE, 0x8D, 0x39
		//};

		apriv = RSA_new();

		f = fopen("privKeySender.pem", "r");
		apriv = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
		fclose(f);

		buf = (unsigned char*)malloc(sizeof(finalDigest));
		memcpy(buf, finalDigest, sizeof(finalDigest));

		// e_data buffer to store the digital signature; there is one single RSA block for the signature
		e_data = (unsigned char*)malloc(RSA_size(apriv)); //RSA_size => 1024 bits/128 bytes

		RSA_private_encrypt(sizeof(finalDigest), buf, e_data, apriv, RSA_PKCS1_PADDING); // encryption for e-signature made by using the PRIVATE key

		printf("Signature(RSA) = ");
		printf("\n");
		for (int i = 0; i < RSA_size(apriv); i++)
		{
			printf("%02X ", e_data[i]);
		}
		printf("\n");

		// write the content of e_data with digital signature into a file
		fwrite(e_data, RSA_size(apriv), 1, fdst); // write the e-sign into the file

		fclose(fdst);

		free(e_data);
		free(buf);

		RSA_free(apriv);
	}
	else {
		printf("\n Usage mode: OpenSSLProj.exe fSrc.txt eSignFsrc.txt");
		return 1;
	}

	return 0;
}
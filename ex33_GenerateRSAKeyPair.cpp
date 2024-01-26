#include <stdio.h>
#include <malloc.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>


int main()
{
	RSA* rsaKP = NULL;

	// rsaKP = RSA_new(); // allocate storage for RSA openssl structure
	rsaKP = RSA_generate_key(1024, 65535, NULL, NULL); // generate RSA key pair on 1k bits

	RSA_check_key(rsaKP); // validate the previous generated key pair

	FILE* fpPriv = NULL;
	fopen_s(&fpPriv, "privKeyReceiver.pem", "w+"); // create file to store the RSA private key (in PEM format)
	PEM_write_RSAPrivateKey(fpPriv, rsaKP, NULL, NULL, 0, 0, NULL); // get the private key from RSA openssl structure and 
																	// store it in the file in PEM format
	fclose(fpPriv);

	FILE* fpPub = NULL;
	fopen_s(&fpPub, "pubKeyReceiver.pem", "w+"); // create file to store the RSA public key
	PEM_write_RSAPublicKey(fpPub, rsaKP); // get the public key fro RSA openssl structure and
										  // store it in the file in PEM format
	fclose(fpPub);

	RSA_free(rsaKP); // release the storage for RSA openssl structure

	printf("\n The RSA key pair generated! \n");

	return 0;
}
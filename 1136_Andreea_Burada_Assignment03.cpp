#include <stdio.h>
#include <iostream>
#include <string>
#include <string.h>
#include <malloc.h>
#include <openssl/aes.h>

using namespace std;

//Define and implement the class named AESCipher as wrapper for OpenSSL AES cipher
//functionality.The class AESCipher must contain the following items at least :

//1. Static fields for supported AES cipher algorithms (two AES algorithms at least)
//2. Two static fields for crypto operations: encryption and decryption
//3. Constructor(s) to initialize the object AESCipher. Please, document the constructor(s)
//within comments
//4. Methods to pass content to be encrypted/decrypted and to get the
//encrypted / decrypted operation result. Please document within comments any
//method you add
//5. Destructor, if the case

#define KEY_SIZE 256
#define BUFFER_SIZE 48

enum AES_algorithms { ECB_alg = 1, CBC_alg = 2};
enum AES_operations { ENCRYPT, DECRYPT };

class AESCipher {
private:
	AES_algorithms algorithm;
	unsigned char key[KEY_SIZE];
	unsigned char IV[16];

	unsigned char* useECBEncrypt(const unsigned char* input) {
		AES_KEY key;
		AES_set_encrypt_key(this->key, KEY_SIZE, &key);

		unsigned char* ciphertext = (unsigned char*)malloc(BUFFER_SIZE);
		for (unsigned int i = 0; i < strlen((char*)input); i += 16) {
			AES_encrypt(&input[i], &ciphertext[i], &key);
		}
		return ciphertext;
	}

	unsigned char* useECBDecrypt(const unsigned char* input) {
		AES_KEY key;
		AES_set_decrypt_key(this->key, KEY_SIZE, &key);

		unsigned char* plaintext = (unsigned char*)malloc(BUFFER_SIZE);
		for (int i = 0; i < BUFFER_SIZE; i += 16) {
			AES_decrypt(&input[i], &plaintext[i], &key);
		}
		return plaintext;
	}

	unsigned char* useCBCEncrypt(const unsigned char* input, const unsigned char* IV) {
		if (IV == NULL) {
			throw runtime_error("!!! Initialization vector cannot be NULL. Cannot encrypt/decrypt message.");
		}
		memcpy(this->IV, IV, 16);

		AES_KEY key;
		AES_set_encrypt_key(this->key, KEY_SIZE, &key);	

		unsigned char* ciphertext = (unsigned char*)malloc(BUFFER_SIZE);
		AES_cbc_encrypt(input, ciphertext, BUFFER_SIZE, &key, this->IV, AES_ENCRYPT);

		return ciphertext;
	}

	unsigned char* useCBCDecrypt(const unsigned char* input, const unsigned char* IV) {
		if (IV == NULL) {
			throw runtime_error("!!! Initialization vector cannot be NULL. Cannot encrypt/decrypt message.");
		}
		memcpy(this->IV, IV, 16);

		AES_KEY key;
		AES_set_decrypt_key(this->key, KEY_SIZE, &key);

		unsigned char* plaintext = (unsigned char*)malloc(BUFFER_SIZE);
		AES_cbc_encrypt(input, plaintext, BUFFER_SIZE, &key, this->IV, AES_DECRYPT);

		return plaintext;
	}

public:
	// input: algorithm - ECB or CBC
	// key - unsigned byte array of length 256
	AESCipher(AES_algorithms algorithm, const unsigned char* key) {
		this->setAlgorithm(algorithm);
		this->setKey(key);
	}

	void setKey(const unsigned char* key) {
		memcpy(this->key, key, KEY_SIZE);
	}

	void setAlgorithm(const AES_algorithms algorithm) {
		this->algorithm = algorithm;
	}

	AES_algorithms getAlgorithm() {
		return this->algorithm;
	}

	// method will encrypt or decrypt by case using the key and IV provided (if necessary)
	// input - unsigned byte array representing either plaintext or ciphertext depending on the operation
	// operation - encrypt or decrypt
	// IV - unsigned byte array, is NULL in the case of ECB
	// output: unsigned byte array representing the encrypted plaintext or decrypted ciphertext
	unsigned char* useAESCipher(const unsigned char* input, AES_operations operation, const unsigned char* IV = NULL) {
		if (!this->algorithm) {
			throw runtime_error("!!! Algorithm not initialized for AESCipher object.");
		}

		if (strlen((char*)input) < 1) {
			cout << "\nInput is empty. Cannot encrypt/decrypt message.";
			return NULL;
		}

		switch (this->algorithm) {
		case ECB_alg:
			switch (operation) {
			case ENCRYPT:
				return this->useECBEncrypt(input);
			case DECRYPT:
				return this->useECBDecrypt(input);
			}
		case CBC_alg:
			switch (operation) {
			case ENCRYPT:
				return this->useCBCEncrypt(input, IV);
			case DECRYPT:
				return this->useCBCDecrypt(input, IV);
			}
		default:
			throw runtime_error("!!! Cannot encrypt/decrypt message. Algorithm type not supported.");
		}
	}

	static void printPlaintext(const char* plaintext) {
		printf("%s", plaintext);
	}

	static void printCiphertext(const unsigned char* ciphertext) {
		for (int i = 0; i < 16; i++) {
			printf("%02X ", ciphertext[i]);
		}
	}

	static const AES_algorithms ecb;
	static const AES_algorithms cbc;
	static const AES_operations encrypt;
	static const AES_operations decrypt;
};

const AES_algorithms AESCipher::ecb = AES_algorithms::ECB_alg;
const AES_algorithms AESCipher::cbc = AES_algorithms::CBC_alg;
const AES_operations AESCipher::encrypt = AES_operations::ENCRYPT;
const AES_operations AESCipher::decrypt = AES_operations::DECRYPT;

void main() {
	try {
		const unsigned char ecbKey[] = {
			0x61, 0x62, 0x41, 0x64, 0x20, 0x77, 0x61, 0x31, 
			0x66, 0x73, 0x26, 0x25, 0x61, 0x63, 0x20, 0x61, 
			0x63, 0x7a, 0x20, 0x77, 0x61, 0x20, 0x36, 0x34, 
			0x20, 0x6e, 0x62, 0x66, 0x64, 0x20, 0x73, 0x33
		};

		AESCipher ecbTest(AESCipher::ecb, ecbKey);

		// encrypt using ecb
		char ecbPlaintext[] = "ECB input test";
		cout << "\nECB Plaintext -> " << ecbPlaintext;
		unsigned char* ecbEncryptResult = ecbTest.useAESCipher((const unsigned char*) ecbPlaintext, AESCipher::encrypt);
		cout << "\nECB Ciphertext -> ";
		AESCipher::printCiphertext(ecbEncryptResult);

		// decrypt using ecb
		char* ecbDecryptResult = (char*) ecbTest.useAESCipher(ecbEncryptResult, AESCipher::decrypt);
		cout << "\nECB Restored plaintext -> ";
		AESCipher::printPlaintext(ecbDecryptResult);

		unsigned char ok = 1;
		for (int i = 0; i < strlen(ecbPlaintext) && ok == 1; i++) {
			if (ecbPlaintext[i] != ecbDecryptResult[i])
				ok = 0;
		}
		if (ok)
			cout << "\nEncryption/decryption successful!";
		else
			cout << "\nEncryption/decryption failed...";

		cout << endl;

		const unsigned char cbcKey[] = {
			0x01, 0x02, 0x03, 0x03, 0x44, 0x51, 0x52, 0x53,
			0xaa, 0xbb, 0xcd, 0xdd, 0xee, 0xff, 0x0b, 0xa0,
			0x11, 0x34, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			0x0f, 0x0f, 0x0f, 0x0f, 0xf0, 0xf0, 0xf0, 0xf0
		};

		const unsigned char IV[] = {
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			0x01, 0x02, 0x03, 0x4, 0xff, 0xff, 0xff, 0xff
		};

		AESCipher cbcTest(AESCipher::cbc, cbcKey);

		// encrypt using cbc
		char cbcPlaintext[] = "CBC input test";
		cout << "\nCBC Plaintext -> " << cbcPlaintext;
		unsigned char* cbcEncryptResult = cbcTest.useAESCipher((const unsigned char*)cbcPlaintext, AESCipher::encrypt, IV);
		cout << "\nCBC Ciphertext -> ";
		AESCipher::printCiphertext(cbcEncryptResult);

		// decrypt using ecb
		char* cbcDecryptResult = (char*)cbcTest.useAESCipher(cbcEncryptResult, AESCipher::decrypt, IV);
		cout << "\nCBC Restored plaintext -> ";
		AESCipher::printPlaintext(cbcDecryptResult);

		ok = 1;
		for (int i = 0; i < strlen(cbcPlaintext) && ok == 1; i++) {
			if (cbcPlaintext[i] != cbcDecryptResult[i])
				ok = 0;
		}
		if (ok)
			cout << "\nEncryption/decryption successful!";
		else
			cout << "\nEncryption/decryption failed...";

		free(ecbEncryptResult);
		free(ecbDecryptResult);
		free(cbcEncryptResult);
		free(cbcDecryptResult);
	}
	catch (exception& e) {
		cout << "\n\nError! - " << e.what();
	}
}
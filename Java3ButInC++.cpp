// Disable CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 

// Include necessary libraries
#include <iostream>
#include <cstdio>
#include <string>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <malloc.h>
#include <memory.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

// Use the standard namespace
using namespace std;

// Main function
int main()
{
    // Read from file in C
    FILE* file;
    long fileSize;
    unsigned char* buffer; // note: sizeof(buffer) is 4 because a pointer is 4 bytes

    // Open the file for binary reading using fopen_s
    if (fopen_s(&file, "response.txt", "rb") != 0) {
        perror("Error opening the file");
        return 1; // Return an error code
    }

    // Determine the file size
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the byte array
    buffer = (unsigned char*)malloc(fileSize);
    if (buffer == NULL) {
        perror("Error allocating memory");
        fclose(file);
        return 1; // Return an error code
    }

    fread(buffer, 1, fileSize, file); // buffer gets content of response.txt

    // Close the file
    fclose(file);

    // Random AES 128-bit key.
    unsigned char key128[16]; // 128 bits = 16 bytes

    if (RAND_bytes(key128, sizeof(key128)) != 1) {
        // Handle error: the random number generator failed
        fprintf(stderr, "Error generating random bytes.\n");
        return 1;
    }

    printf("\nGenerated AES 128-bit key:\n");
    for (int i = 0; i < sizeof(key128); i++) {
        printf("%02x", key128[i]);
    }

    unsigned char ciphertext[48];

    printf("\n");

    AES_KEY aes_key; // AES key structure

    // Set the encryption key for AES-128
    AES_set_encrypt_key(key128, (sizeof(key128) * 8), &aes_key);

    // Encryption using AES-ECB mode in 16-byte blocks
    for (unsigned int i = 0; i < sizeof(buffer); i += 16)
        AES_encrypt(&buffer[i], &ciphertext[i], &aes_key);

    // ciphertext contains the content of response.txt

    // Display the ciphertext in hexadecimal format
    printf("\nCiphertext for response.txt in AES-ECB: ");
    for (unsigned int i = 0; i < sizeof(ciphertext); i++)
        printf(" %02X", ciphertext[i]);
    printf("\n");

    unsigned char restoringtext[48];

    // Set the decryption key for AES-192
    AES_set_decrypt_key(key128, (sizeof(key128) * 8), &aes_key);

    // Decryption using AES-ECB mode in 16-byte blocks
    for (unsigned int i = 0; i < sizeof(ciphertext); i += 16)
        AES_decrypt(&ciphertext[i], &restoringtext[i], &aes_key);

    // Display the restored plaintext in hexadecimal format
    printf("Restored plaintext for AES-ECB: ");
    for (unsigned int i = 0; i < fileSize; i++)
        printf("%c", restoringtext[i]);
    printf("\n");

    // Free allocated memory
    free(buffer);

    FILE* fdst = NULL;
    errno_t err;

    // RSA encryption
    EVP_PKEY* evp_key;
    FILE* f;

    unsigned char* e_data = NULL;

    // Load X.509 certificate from file
    err = fopen_s(&f, "SimplePGP_ISM.cer", "r");
    if (err) {
        fprintf(stderr, "Error opening certificate file.\n");
        return 1;
    }

    X509* x509 = d2i_X509_fp(f, NULL); // for .cer
    fclose(f);

    if (!x509) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Extract public key from the certificate
    evp_key = X509_get_pubkey(x509);
    X509_free(x509);

    if (!evp_key) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Extract RSA key from EVP_PKEY
    RSA* apub = EVP_PKEY_get1_RSA(evp_key);
    EVP_PKEY_free(evp_key);

    if (!apub) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Allocate buffer for encrypted data
    e_data = (unsigned char*)malloc(RSA_size(apub));

    err = fopen_s(&fdst, "aesKey.sec", "wb");

    // Encryption
    RSA_public_encrypt(48, ciphertext, e_data, apub, RSA_PKCS1_PADDING);
    fwrite(e_data, sizeof(unsigned char), RSA_size(apub), fdst);

    // Print e_data to the console
    printf("Encrypted Data:\n");
    for (int i = 0; i < RSA_size(apub); ++i) {
        printf("%02x ", e_data[i]);
    }
    printf("\n");

    // Cleanup
    free(e_data);
    RSA_free(apub);
    fclose(fdst);

    return 0;
}

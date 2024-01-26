#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define INBUFSIZE 512
#define OUTBUFSIZE (512*512)

void prtErrAndExit(int eVal, char* msg);
int main(int argc, char* argv[]);

int main(int argc, char* argv[]) {
    int outBytes, tmpOutBytes, bytesInBuf, i;
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
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    cipherBlockSize = EVP_CIPHER_CTX_block_size(ctx);
    cipherKeyLength = EVP_CIPHER_CTX_key_length(ctx);
    cipherIvLength = EVP_CIPHER_CTX_iv_length(ctx);

    fprintf(stderr, "INFO(evp_decrypt): Enc Algo:   %s\n", OBJ_nid2ln(EVP_CIPHER_CTX_nid(ctx)));
    fprintf(stderr, "INFO(evp_decrypt): Key:        ");
    for (i = 0; i < cipherKeyLength; i++)
        fprintf(stderr, "%02X", (int)(key[i]));
    fprintf(stderr, "\n");
    fprintf(stderr, "INFO(evp_decrypt): IV:         ");
    for (i = 0; i < cipherIvLength; i++)
        fprintf(stderr, "%02X", (int)(iv[i]));
    fprintf(stderr, "\n");
    fprintf(stderr, "INFO(evp_decrypt): block size: %d\n", cipherBlockSize);
    fprintf(stderr, "INFO(evp_decrypt): key length: %d\n", cipherKeyLength);
    fprintf(stderr, "INFO(evp_decrypt): IV length:  %d\n", cipherIvLength);

    if ((cipherKeyLength > 32) || (cipherIvLength > 16))
        prtErrAndExit(1, (char*)"ERROR: Hardwired key or iv was too short!!\n");

    // decrypt text file
    FILE* ft;
    ft = fopen("str_txt.enc", "r");

    unsigned int plaintext_length;
    fscanf(ft, "%u\n", &plaintext_length);
    unsigned char infile_buffer[INBUFSIZE];
    fscanf(ft, "%s", infile_buffer);

    unsigned char* ptr, pair[2];
    ptr = infile_buffer;
    for (unsigned char i = 0; i < strlen((const char*)infile_buffer); i += 2)
    {
        memcpy(pair, ptr, 2); // each hex pair has 2 bytes
        buf2crypt[i / 2] = (unsigned char)strtol((const char*)pair, NULL, 16);
        ptr += 2; // each hex pair has 2 bytes
    }
    bytesInBuf = strlen((const char*)infile_buffer) / 2; // each hex pair has 2 bytes
    outBytes = 0; // offset of the 1st byte within outBuf containing the restored plaintext

    if (!EVP_DecryptUpdate(ctx, outBuf + outBytes, &tmpOutBytes, buf2crypt, bytesInBuf))
        prtErrAndExit(1, (char*)"ERROR: EVP_DecryptUpdate didn't work...\n");
    outBytes += tmpOutBytes;

    if ((OUTBUFSIZE - (cipherBlockSize + outBytes)) <= 0)
        prtErrAndExit(1, (char*)"ERROR: Buffer was not big enough to hold decrypted data!!\n");
    if (!EVP_DecryptFinal_ex(ctx, outBuf + outBytes, &tmpOutBytes))
        prtErrAndExit(1, (char*)"ERROR: EVP_DecryptFinal_ex didn't work...\n");
    outBytes += tmpOutBytes;

    fprintf(stderr, "\n\nINFO(evp_decrypt): Bytes in (text file):   %d\n", bytesInBuf);
    fprintf(stderr, "INFO(evp_decrypt): Bytes out (text file):  %d\n", plaintext_length);

    // EVP_CIPHER_CTX_cleanup(ctx);

    outBuf[plaintext_length] = 0; // put the string terminator right after the last byte of the initial plaintext
    fprintf(stderr, "\nRestored plaintext from the encrypted text file ---> %s\n", outBuf);

    fclose(ft);

    // decrypt binary file
    FILE* fb;
    fb = fopen("str_bin.enc", "rb");

    // ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    cipherBlockSize = EVP_CIPHER_CTX_block_size(ctx);
    cipherKeyLength = EVP_CIPHER_CTX_key_length(ctx);
    cipherIvLength = EVP_CIPHER_CTX_iv_length(ctx);

    if ((cipherKeyLength > 32) || (cipherIvLength > 16))
        prtErrAndExit(1, (char*)"ERROR: Hardwired key or iv was too short!!\n");

    unsigned int infile_length;
    fseek(fb, 0, SEEK_END);
    infile_length = ftell(fb);
    fseek(fb, 0, SEEK_SET);

    fread(buf2crypt, infile_length, 1, fb);

    outBytes = 0; // offset of the 1st byte within outBuf containing the restored plaintext

    if (!EVP_DecryptUpdate(ctx, outBuf + outBytes, &tmpOutBytes, buf2crypt, infile_length))
        prtErrAndExit(1, (char*)"ERROR: EVP_DecryptUpdate didn't work...\n");
    outBytes += tmpOutBytes;

    if ((OUTBUFSIZE - (cipherBlockSize + outBytes)) <= 0)
        prtErrAndExit(1, (char*)"ERROR: Buffer was not big enough to hold decrypted data!!\n");
    if (!EVP_DecryptFinal_ex(ctx, outBuf + outBytes, &tmpOutBytes))
        prtErrAndExit(1, (char*)"ERROR: EVP_DecryptFinal_ex didn't work...\n");
    outBytes += tmpOutBytes;

    fprintf(stderr, "INFO(evp_decrypt): Bytes in (binary file):   %d\n", infile_length);
    fprintf(stderr, "INFO(evp_decrypt): Bytes out (binary file):  %d\n", plaintext_length);

    EVP_CIPHER_CTX_cleanup(ctx);

    outBuf[plaintext_length] = 0; // put the string terminator right after the last byte of the initial plaintext
    fprintf(stderr, "\nRestored plaintext from the encrypted binary file ---> %s\n", outBuf);

    fclose(fb);

    return 1;
} /* end func main */

/* Save some vertical space with this simple error handling function.. */
void prtErrAndExit(int eVal, char* msg) {
    if (msg != NULL)
        fprintf(stderr, "INFO(evp_decrypt): %s\n\n", msg);
    exit(eVal);
} /* end func prtErrAndExit */
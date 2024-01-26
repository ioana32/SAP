#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <openssl/applink.c>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

int main()
{
    X509* X509Cert = X509_new();

    X509_set_version(X509Cert, 0x2);

    ASN1_INTEGER_set(X509_get_serialNumber(X509Cert), 1);

    X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "C", MBSTRING_ASC, (unsigned char*)"RO", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "O", MBSTRING_ASC, (unsigned char*)"ASE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "OU", MBSTRING_ASC, (unsigned char*)"ITC Security Master", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "CN", MBSTRING_ASC, (unsigned char*)"Marius Popa", -1, -1, 0);

    X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "C", MBSTRING_ASC, (unsigned char*)"RO", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "O", MBSTRING_ASC, (unsigned char*)"ASE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "OU", MBSTRING_ASC, (unsigned char*)"ITC Security Master", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "CN", MBSTRING_ASC, (unsigned char*)"Marius Popa", -1, -1, 0);

    int DaysStart = 1;
    int DaysStop = 7;
    X509_gmtime_adj(X509_get_notBefore(X509Cert), (long)60 * 60 * 24 * DaysStart);
    X509_gmtime_adj(X509_get_notAfter(X509Cert), (long)60 * 60 * 24 * DaysStop);

    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(1024, 65535, NULL, NULL);
    EVP_PKEY_set1_RSA(pkey, rsa);
    X509_set_pubkey(X509Cert, pkey);

    const EVP_MD* dgAlg = EVP_sha1();

    X509_sign(X509Cert, pkey, dgAlg);

    BIO* out1 = BIO_new_file("SampleCert.cer", "w");
    i2d_X509_bio(out1, X509Cert);
    BIO_free(out1);

    BIO* out2 = BIO_new_file("privateKeyCert.key", "w");
    i2d_PrivateKey_bio(out2, pkey);
    BIO_free(out2);

    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    X509_free(X509Cert);
}
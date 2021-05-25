#include "multitool_evp.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/err.h>
#include <string.h>

/*
 * int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                            const unsigned char *salt, int saltlen, int iter,
                            int keylen, unsigned char *out);
 *
*/




int keygen_evp(keyIVpair *keyParams)
{
    int keyLen = 32;
    int ivLen = 16;
    int saltLen = 32;
    int passLen = 25;
    //This is mostly here to prevent pre-computed rainbow tables. That's why it's hardcoded
    //How the salt should actually be used is discussed in the report.
    unsigned char saltTable[] = {"46145a20dd1a10e0bdc844cafcd0a1fe"};

    unsigned char keyOut[keyLen];
    unsigned char ivOut[ivLen];
    keyParams->key = keyOut;
    keyParams->iv = ivOut;



    deriveStruct *deriveParams = (deriveStruct *) malloc(sizeof(deriveStruct));

    if(!deriveParams)
    {
        printf("MALLOC FAIL\n");
        cleanup(keyParams, deriveParams);
        return 0;
    }
    deriveParams->salt = saltTable;

    char password[passLen];
    deriveParams->pass = password;
    printf("Insert password\n");
    fflush(stdin);
    fflush(stdout);
    if (fgets(deriveParams->pass, passLen, stdin) == NULL)
    {
        printf("FGETS Fail\n");
        cleanup(keyParams, deriveParams);
        return 0;
    }

    if (PKCS5_PBKDF2_HMAC(deriveParams->pass, -1, deriveParams->salt, saltLen, 50000,EVP_sha256(), sizeof(keyParams->key), keyParams->key) == 0)
    {
        printf("PBKDF2 Fail\n");
        cleanup(keyParams, deriveParams);
        return 0;
    }
    if (PKCS5_PBKDF2_HMAC(deriveParams->pass, -1, deriveParams->salt, saltLen, 5000,EVP_sha256(), sizeof(keyParams->iv), keyParams->iv) == 0)
    {
        printf("PBKDF2 Fail\n");
        cleanup(keyParams, deriveParams);
        return 0;
    }


    OPENSSL_cleanse(deriveParams->pass, sizeof(deriveParams->pass));
    free(deriveParams);
    return 1;
}

int crypt_evp(int mode, char filePath[])
{
    //For transparency, the encryption operation is based on the example found at https://www.openssl.org/docs/man1.1.1/man3/EVP_EncryptInit.html

    unsigned char inBuf[1024], outBuf[1024+128];
    int inLen, outLen;
    FILE *fileIn;
    FILE *fileOut;
    fileIn =fopen(filePath, "rb");
    if (mode == 0)
    {
        fileOut = fopen("Decrypted", "wb");
    }
    else
    {
        fileOut = fopen("Encrypted.enc", "wb");
    }

    if (fileIn == NULL || fileOut == NULL)
    {
        printf("File can't be opened or it doesn't exist\n");
        return 0;
    }

    keyIVpair* keys = (keyIVpair*) malloc(sizeof(keyIVpair));
    if(!keys)
    {
           printf("Can't allocate to heap\n");
           return 0;
    }

    if(!keygen_evp(keys))
    {
        printf("Error while generating keys\n");
        fclose(fileIn); fclose(fileOut);
        free(keys);
        return 0;
    }
    EVP_CIPHER_CTX *ctx;
    printf("KEY = %s, IV = %s\n", keys->key, keys->iv);
    ctx = EVP_CIPHER_CTX_new(); //This one shouldn't fail
    if(!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, mode))
    {
        printf("Error during EVP_CipherInit_ex \n");
        fclose(fileIn); fclose(fileOut);
        free(keys);
        return 0;
    }
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    if(!EVP_CipherInit_ex(ctx, NULL, NULL, keys->key, keys->iv, mode))
    {
        printf("Error in EVP_CipherInit_ex while setting key and IV \n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fileIn); fclose(fileOut);
        free(keys);
        return 0;
    }

    for(;;)
    {
        inLen = fread(inBuf, 1, 1024, fileIn);

        if(!EVP_CipherUpdate(ctx, outBuf, &outLen, inBuf, inLen))
        {
            printf("Error during encrypt/decrypt\n");
            fprintf(stderr, "ERROR: EVP_CipherUpdate_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            fclose(fileIn); fclose(fileOut);
            free(keys);
            return 0;
        }
        fwrite(outBuf, sizeof(unsigned char), outLen, fileOut);
        if (inLen < 1024)
        {
            break;
        }
    }
    if (!EVP_CipherFinal_ex(ctx, outBuf, &outLen))
    {

        printf("Error during encrypt/decrypt\n");
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        fclose(fileIn); fclose(fileOut);
        free(keys);
        return 0;
    }
    fwrite(outBuf, sizeof(unsigned char) ,outLen, fileOut);
    EVP_CIPHER_CTX_free(ctx);
    fclose(fileIn);
    fclose(fileOut);
    free(keys);
    return 1;
}

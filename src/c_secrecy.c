#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "c_secrecy.h"

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    printf("errors\n");
}

// Uses the key to decrypt the value
void expose_secret(Secret_t *secret, uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        return;
    }
    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, secret->key, secret->iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, secret->value, secret->ciphertext_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }  
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

// Generates a key and stores the value
// data is the pointer to the start of the data
// size is the size in bytes of the data e.g. a uint32 would be 4
Secret_t *create_secret(uint8_t *data, uint64_t size)
{
    EVP_CIPHER_CTX *ctx;

    int len, ciphertext_len;

    uint8_t ciphertext[SECRET_BUFFER_SIZE_MAX];

    int rc = 0;
    uint8_t key[SECRET_KEY_SIZE];
    uint8_t iv[SECRET_IV_SIZE];

    if (size > SECRET_BUFFER_SIZE_MAX)
    {
        // set error string
        errno = EINVAL;
        return NULL;
    }

    // generate keys
    rc = RAND_bytes(key, SECRET_KEY_SIZE);
    rc = RAND_bytes(iv, SECRET_IV_SIZE);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        // set errno / error string
        return NULL;
    }
    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        // set errno / error string
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, data, size))
    {
        // set errno / error string
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        // set errno / error string
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len += len;

    if (ciphertext_len > SECRET_BUFFER_SIZE_MAX)
    {
        EVP_CIPHER_CTX_free(ctx);
        // set error string
        errno = EINVAL;
        return NULL;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    Secret_t *secret;
    secret = (Secret_t *)malloc(sizeof(Secret_t));
    if (secret == NULL)
    {
        // set errno
        return NULL;
    }

    memset(secret->value, 0, SECRET_BUFFER_SIZE_MAX * sizeof(uint8_t));

    secret->size = size;
    secret->ciphertext_len = ciphertext_len;
    
    memcpy(secret->value, ciphertext, ciphertext_len * sizeof(uint8_t));
    memcpy(secret->key, key, SECRET_KEY_SIZE * sizeof(uint8_t));
    memcpy(secret->iv, iv, SECRET_IV_SIZE * sizeof(uint8_t));

    return secret;
}

void __attribute__((optimize("O0"))) clear_secret(Secret_t *secret)
{
    // comments that this could be compiled out, memset_s solves this but was introduced in C11
    memset(secret->value, 0, SECRET_BUFFER_SIZE_MAX * sizeof(uint8_t));
    memset(secret->key, 0, SECRET_KEY_SIZE * sizeof(uint8_t));
    memset(secret->iv, 0, SECRET_IV_SIZE * sizeof(uint8_t));
    secret->size = 0;
    secret->ciphertext_len = 0;
}

void delete_secret(Secret_t *secret)
{
    clear_secret(secret);

    // check success
    free(secret);
}
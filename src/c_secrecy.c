#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// test mock openssl
#ifdef DEBUG
#include <test_mock_openssl.h>

#else

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#endif

#include "c_secrecy.h"
#include "c_secrecy_error.h"

#define MIN(i, j) (((i) < (j)) ? (i) : (j))

/*
    Uses the key to decrypt the value
*/
void expose_secret(Secret_t *secret, uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        // errno
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
        // errno
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, secret->value, secret->ciphertext_len))
    {
        // errno
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

/*
    Generates the key and iv for the secret encryption
*/
int generate_keys(uint8_t *key, uint8_t *iv)
{
    int rc = 0;

    // needs error handling
    rc = RAND_bytes(key, SECRET_KEY_SIZE);
    if (rc != 1)
    {
        return ERR_RAND_CREATE_KEY;
    }

    rc = RAND_bytes(iv, SECRET_IV_SIZE);
    if (rc != 1)
    {
        return ERR_RAND_CREATE_IV;
    }

    return SUCCESS;
}

/*
    Generates a key and stores the value
    data is the pointer to the start of the data
    size is the size in bytes of the data e.g. a uint32 would be 4

    Note: Once this is called, the value for the data should be deleted or cleared immediately as it is
    an unsecure store of data. memset and free where necessary
*/

Secret_t *create_secret(uint8_t *data, uint64_t size)
{
    EVP_CIPHER_CTX *ctx;

    int len, ciphertext_len, ciphertext_len_min;
    uint8_t *ciphertext;

    int rc = 0;
    uint8_t key[SECRET_KEY_SIZE];
    uint8_t iv[SECRET_IV_SIZE];

    // calculate the minimum length possible for the ciphertext
    ciphertext_len_min = MIN(size * 2, SECRET_KEY_SIZE * 2);

    // generate keys
    rc = generate_keys(key, iv);
    if (rc != SUCCESS)
    {
        //c_secrecy_errno = E_GEN_KEY_ERROR;
        return NULL;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        //c_secrecy_errno = E_CREATE_CIPHER_CTX;
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
    ciphertext = (uint8_t *)malloc(sizeof(uint8_t)*ciphertext_len_min);
    if (ciphertext == NULL)
    {
        // errno
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, data, size))
    {
        // set errno / error string
        free(ciphertext);
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
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len += len;

    // finished with the cipeher context here, clean up
    EVP_CIPHER_CTX_free(ctx);

    // create and allocate the secret 
    Secret_t *secret;

    secret = (Secret_t *)malloc(sizeof(Secret_t));
    if (secret == NULL)
    {
        // set errno
        free(ciphertext);
        return NULL;
    }

    // double the size so that we know we have enough for the ciphertext
    secret->value = (uint8_t *)malloc(sizeof(uint8_t) * ciphertext_len);
    if (secret->value == NULL)
    {
        // set errno
        free(ciphertext);
        free(secret);
        return NULL;
    }

    // clear out the memory location
    memset(secret->value, 0, sizeof(uint8_t) * ciphertext_len);

    secret->size = size;
    secret->ciphertext_len = ciphertext_len;
    
    memcpy(secret->value, ciphertext, ciphertext_len * sizeof(uint8_t));

    // no longer need the ciphertext here, clear it out
    free(ciphertext);
    
    memcpy(secret->key, key, SECRET_KEY_SIZE * sizeof(uint8_t));
    memcpy(secret->iv, iv, SECRET_IV_SIZE * sizeof(uint8_t));

    return secret;
}

/*
    Clears out all the secret memory locations
*/
void __attribute__((optimize("O0"))) clear_secret(Secret_t *secret)
{
    // comments that this could be compiled out, memset_s solves this but was introduced in C11
    memset(secret->value, 0, sizeof(uint8_t) * secret->ciphertext_len);
    memset(secret->key, 0, SECRET_KEY_SIZE * sizeof(uint8_t));
    memset(secret->iv, 0, SECRET_IV_SIZE * sizeof(uint8_t));
    secret->size = 0;
    secret->ciphertext_len = 0;
}

void delete_secret(Secret_t *secret)
{
    clear_secret(secret);

    // clear out the secret value
    free(secret->value);

    // check success
    free(secret);
}
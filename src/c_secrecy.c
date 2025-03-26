#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "c_secrecy.h"
#include "c_secrecy_error.h"

#include <pthread.h>

#define MIN(i, j) (((i) < (j)) ? (i) : (j))

__thread int c_secrecy_errno;

/*
    Uses the key to decrypt the value
*/
void expose_secret(Secret_t *secret, uint8_t *plaintext, const int plaintext_buffer_len)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;
    c_secrecy_errno = 0;

    if (secret->value_len > plaintext_buffer_len)
    {
        c_secrecy_errno = ERR_P_TEXT_LEN_ERROR;
        return;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        c_secrecy_errno = ERR_CREATE_CIPHER_CTX;
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
        c_secrecy_errno = ERR_DEC_INIT_ERROR;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, secret->value, secret->ciphertext_len))
    {
        c_secrecy_errno = ERR_DEC_UPDATE_ERROR;
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
        c_secrecy_errno = ERR_DEC_FINAL_ERROR;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

const uint8_t *expose_secret_inline(Secret_t *secret)
{
    uint8_t *plaintext;

    c_secrecy_errno = 0;

    plaintext = (uint8_t *)malloc(secret->value_len);
    if (plaintext == NULL)
    {
        c_secrecy_errno = ERR_P_TEXT_ALLOC_ERROR;
        return NULL;
    }

    expose_secret(secret, plaintext, secret->value_len);

    return plaintext;
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

    c_secrecy_errno = 0;

    // calculate the minimum length possible for the ciphertext
    ciphertext_len_min = MIN(size * 2, SECRET_KEY_SIZE * 2);

    // generate keys
    rc = generate_keys(key, iv);
    if (rc != SUCCESS)
    {
        c_secrecy_errno = ERR_GEN_KEY_ERROR;
        return NULL;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        c_secrecy_errno = ERR_CREATE_CIPHER_CTX;
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
        c_secrecy_errno = ERR_ENC_INIT_ERROR;
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
        c_secrecy_errno = ERR_C_TEXT_ALLOC;
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, data, size))
    {
        c_secrecy_errno = ERR_ENC_UPDATE_ERROR;
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
        c_secrecy_errno = ERR_ENC_FINAL_ERROR;
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
        c_secrecy_errno = ERR_SEC_ALLOC_ERROR;
        free(ciphertext);
        return NULL;
    }

    // double the size so that we know we have enough for the ciphertext
    secret->value = (uint8_t *)malloc(sizeof(uint8_t) * ciphertext_len);
    if (secret->value == NULL)
    {
        c_secrecy_errno = ERR_SEC_VAL_ALLOC_ERROR;
        free(ciphertext);
        free(secret);
        return NULL;
    }

    // clear out the memory location
    memset(secret->value, 0, sizeof(uint8_t) * ciphertext_len);

    secret->value_len = size;
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
    if (secret->value != NULL)
    {
        memset(secret->value, 0, sizeof(uint8_t) * secret->ciphertext_len);
        
        // this is currently not working but I'm not sure why
        // memset_s(secret->value, 0, sizeof(uint8_t) * secret->ciphertext_len);
    }

    memset(secret->key, 0, SECRET_KEY_SIZE * sizeof(uint8_t));
    memset(secret->iv, 0, SECRET_IV_SIZE * sizeof(uint8_t));

    // this is currently not working but I'm not sure why
    // memset_s(secret->key, SECRET_KEY_SIZE * sizeof(uint8_t), 0, SECRET_KEY_SIZE * sizeof(uint8_t));
    // memset_s(secret->iv, SECRET_IV_SIZE * sizeof(uint8_t), 0, SECRET_IV_SIZE * sizeof(uint8_t));

    secret->value_len = 0;
    secret->ciphertext_len = 0;
}

/*
    Only valid if you have a heap secret
*/
void delete_secret(Secret_t *secret)
{
    c_secrecy_errno = 0;
    
    if (secret == NULL)
    {
        c_secrecy_errno = ERR_SEC_DEL_NULL_ERROR;
        return;
    }

    clear_secret(secret);

    if (secret->value != NULL)
    {
        free(secret->value);
    }
    
    free(secret);
}
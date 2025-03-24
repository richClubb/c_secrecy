#ifndef __C_SECRECY__

#define __C_SECRECY__

// system
#include <stdint.h>

// external includes
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

// internal includes

// these could be configurable?
#define SECRET_KEY_SIZE 32
#define SECRET_IV_SIZE 16

#define ERR_RAND_CREATE_KEY 1
#define ERR_RAND_CREATE_IV 2
#define SUCCESS 0

typedef struct {
    char *value;
    uint8_t key[SECRET_KEY_SIZE];
    uint8_t iv[SECRET_IV_SIZE];
    uint64_t size;
    uint64_t ciphertext_len;
} Secret_t;

// Uses the key to decrypt the value
void expose_secret(Secret_t *, uint8_t *);

// Generates a key and stores the value
Secret_t *create_secret(uint8_t *, uint64_t);

void delete_secret(Secret_t *);

#endif 
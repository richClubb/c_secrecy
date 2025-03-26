#ifndef __C_SECRECY_ERROR__

#define __C_SECRECY_ERROR__

#include <pthread.h>

extern __thread int c_secrecy_errno;

extern __thread char *c_secrecy_errstr;

#define ERR_CREATE_CIPHER_CTX 1
#define ERR_GEN_KEY_ERROR 2
#define ERR_RAND_CREATE_KEY 3
#define ERR_RAND_CREATE_IV 4

#endif
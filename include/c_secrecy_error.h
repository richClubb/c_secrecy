#ifndef __C_SECRECY_ERROR__

#define __C_SECRECY_ERROR__

#include <pthread.h>

extern __thread int c_secrecy_errno;

extern __thread char *c_secrecy_errstr;

#define ERR_CREATE_CIPHER_CTX    1
#define ERR_GEN_KEY_ERROR        2
#define ERR_RAND_CREATE_KEY      3
#define ERR_RAND_CREATE_IV       4
#define ERR_ENC_INIT_ERROR       5
#define ERR_C_TEXT_ALLOC         6
#define ERR_ENC_UPDATE_ERROR     7
#define ERR_ENC_FINAL_ERROR      8
#define ERR_SEC_ALLOC_ERROR      9
#define ERR_SEC_VAL_ALLOC_ERROR 10
#define ERR_SEC_DEL_NULL_ERROR  11
#define ERR_P_TEXT_LEN_ERROR    12
#define ERR_DEC_INIT_ERROR      13
#define ERR_DEC_UPDATE_ERROR    14
#define ERR_DEC_FINAL_ERROR     15
#define ERR_P_TEXT_ALLOC_ERROR  16

#endif
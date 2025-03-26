#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <stdio.h>

#include "c_secrecy.h"
#include "c_secrecy_error.h"

void test_basic_char(void)
{
    char data = 't';
    char *ptr;
    uint8_t buffer[sizeof(uint8_t)*1];
    uint32_t size;
    
    Secret_t *secret = create_secret(&data, sizeof(char));
    CU_ASSERT_NOT_EQUAL_FATAL(secret, NULL); // bomb out if this is bad as we can't continue

    CU_ASSERT_NOT_EQUAL((char)*secret->value, 't');

    expose_secret(secret, buffer, 1);

    CU_ASSERT_EQUAL((char)*buffer, 't');

    delete_secret(secret);

    // can't check the memory location or we get a segfault. Gonna have to trust us bro.
}

void test_basic_char_array(void)
{
    char *data = "test";
    
    uint8_t buffer[sizeof(uint8_t)*4];
    uint8_t comp_buffer[sizeof(uint8_t)*4];
    uint32_t size;
    
    Secret_t *secret = create_secret(data, sizeof(char)*4);
    CU_ASSERT_NOT_EQUAL_FATAL(secret, NULL); // bomb out if this is bad as we can't continue

    CU_ASSERT_NOT_EQUAL(strncmp("test", secret->value, 4), 0);

    expose_secret(secret, buffer, 4);

    CU_ASSERT_EQUAL(strncmp("test", buffer, 4), 0);  

    delete_secret(secret);
}

void run_char_suite(void)
{
    
    CU_pSuite suite = CU_add_suite("C secrecy char tests", 0, 0);
    CU_add_test(suite, "test of basic char creation and destruction", test_basic_char);
    CU_add_test(suite, "test of basic char array creation and destruction", test_basic_char_array);

    CU_basic_run_tests();
}
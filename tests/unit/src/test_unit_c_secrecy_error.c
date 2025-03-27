#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <stdio.h>

#include "c_secrecy.h"

void test_error_array_size(void)
{
    char data = 't';
    char *ptr;
    uint8_t buffer[sizeof(uint8_t)*1];
    uint32_t size;
    
    Secret_t *secret = create_secret(&data, sizeof(char));
    CU_ASSERT_NOT_EQUAL_FATAL(secret, NULL);

    // how do I mock the interfaces?

    delete_secret(secret);

    // can't check the memory location or we get a segfault. Gonna have to trust us bro.
}

void test_delete_null_secret(void)
{
    Secret_t *secret;

    // test precondition
    CU_ASSERT_EQUAL_FATAL(secret, NULL);

    // enough to test that we're protecting against accessing a secret that is null
    delete_secret(secret);
}

void test_delete_null_secret_value(void)
{
    Secret_t secret;

    // enough to test that we're protecting against a secret value that is null
    delete_secret(&secret);
}

void load_error_suite(void)
{   
    CU_pSuite suite = CU_add_suite("C secrecy error tests", 0, 0);
    CU_add_test(suite, "test of basic char creation and destruction", test_error_array_size);
}
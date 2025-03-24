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

    CU_ASSERT_NOT_EQUAL((char)*secret->value, 't');

    expose_secret(secret, buffer);

    CU_ASSERT_EQUAL((char)*buffer, 't');

    delete_secret(secret);

    // can't check the memory location or we get a segfault. Gonna have to trust us bro.
}

void run_error_suite(void)
{
    
    CU_pSuite suite = CU_add_suite("C secrecy error tests", 0, 0);
    CU_add_test(suite, "test of basic char creation and destruction", test_error_array_size);

    CU_basic_run_tests();
}
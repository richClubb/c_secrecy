#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <stdio.h>

#include "c_secrecy.h"

void test_basic_int(void)
{
    int data = 450;
    int buffer;
    
    Secret_t *secret = create_secret((uint8_t *)&data, sizeof(int));
    CU_ASSERT_NOT_EQUAL_FATAL(secret, NULL); // bomb out if this is bad as we can't continue

    CU_ASSERT_NOT_EQUAL((int)*secret->value, 450);

    expose_secret(secret, (uint8_t *)&buffer);

    CU_ASSERT_EQUAL((int)buffer, 450);

    delete_secret(secret);

    // can't check the memory location or we get a segfault. Gonna have to trust us bro.
}

void test_basic_int_array(void)
{
    int data[3] = {450, 451, 452};
    int buffer[3];
    
    Secret_t *secret = create_secret((uint8_t *)&data, sizeof(int) * 3);
    CU_ASSERT_NOT_EQUAL_FATAL(secret, NULL); // bomb out if this is bad as we can't continue

    CU_ASSERT_NOT_EQUAL((int)*secret->value, 450);

    expose_secret(secret, (uint8_t *)&buffer);

    CU_ASSERT_EQUAL((int)buffer[0], 450);
    CU_ASSERT_EQUAL((int)buffer[1], 451);
    CU_ASSERT_EQUAL((int)buffer[2], 452);

    delete_secret(secret);
}

void run_int_suite(void)
{
    
    CU_pSuite suite = CU_add_suite("C secrecy int tests", 0, 0);
    CU_add_test(suite, "test of basic int creation and destruction", test_basic_int);
    CU_add_test(suite, "test of basic int array creation and destruction", test_basic_int_array);

    CU_basic_run_tests();
}
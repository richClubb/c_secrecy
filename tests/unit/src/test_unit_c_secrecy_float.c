#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <stdio.h>

#include "c_secrecy.h"

void test_basic_float(void)
{
    float data = 10;
    float buffer;
    
    Secret_t *secret = create_secret((uint8_t *)&data, sizeof(float));
    CU_ASSERT_NOT_EQUAL_FATAL(secret, NULL); // bomb out if this is bad as we can't continue

    CU_ASSERT_NOT_EQUAL((float)*secret->value, 10.0);

    expose_secret(secret, (uint8_t *)&buffer, sizeof(float));

    CU_ASSERT_EQUAL((float)buffer, 10);

    delete_secret(secret);

    // can't check the memory location or we get a segfault. Gonna have to trust us bro.
}

void test_basic_float_array(void)
{
    float data[3] = {10, 11, 12};
    float buffer[3];
    
    Secret_t *secret = create_secret((uint8_t *)&data, sizeof(float)*3);
    CU_ASSERT_NOT_EQUAL_FATAL(secret, NULL); // bomb out if this is bad as we can't continue

    CU_ASSERT_NOT_EQUAL((float)*secret->value, 10.0);

    expose_secret(secret, (uint8_t *)&buffer, sizeof(float) * 3);

    CU_ASSERT_EQUAL(buffer[0], 10);
    CU_ASSERT_EQUAL(buffer[1], 11);
    CU_ASSERT_EQUAL(buffer[2], 12);

    delete_secret(secret);

    // can't check the memory location or we get a segfault. Gonna have to trust us bro.
}

void load_float_suite(void)
{
    CU_pSuite suite = CU_add_suite("C secrecy float tests", 0, 0);
    CU_add_test(suite, "test of basic float creation and destruction", test_basic_float);
    CU_add_test(suite, "test of basic float creation and destruction", test_basic_float_array);
}
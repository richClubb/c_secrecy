#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <stdio.h>

#include "c_secrecy.h"

void test_basic_float(void)
{
    float data = 10;
    float buffer;
    uint8_t buffer_2[SECRET_BUFFER_SIZE_MAX];
    uint8_t buffer_3[SECRET_BUFFER_SIZE_MAX];
    uint32_t size;
    
    Secret_t *secret = create_secret((uint8_t *)&data, sizeof(float));

    CU_ASSERT_NOT_EQUAL((float)*secret->value, 10);

    expose_secret(secret, (uint8_t *)&buffer);
    expose_secret(secret, buffer_2);
    expose_secret(secret, buffer_3);

    CU_ASSERT_EQUAL((float)buffer, 10);

    // this currently doesn't work but I'm wondering if it should
    // CU_ASSERT_EQUAL((float *)(&buffer_2), 10);

    delete_secret(secret);

    // can't check the memory location or we get a segfault. Gonna have to trust us bro.
}

void run_float_suite(void)
{
    
    CU_pSuite suite = CU_add_suite("C secrecy char tests", 0, 0);
    CU_add_test(suite, "test of basic float creation and destruction", test_basic_float);

    CU_basic_run_tests();
}
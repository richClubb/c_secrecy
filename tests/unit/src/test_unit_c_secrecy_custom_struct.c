#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <stdio.h>

#include "c_secrecy.h"

void test_basic_custom_struct(void)
{
    struct userdata {
        char name[30];
        int id;
    };

    struct userdata rich = {
        "rich", 1
    };

    struct userdata buffer;
    struct userdata ptr;

    int test = sizeof(struct userdata);

    Secret_t *secret = create_secret((uint8_t *)&rich, sizeof(struct userdata));
    CU_ASSERT_NOT_EQUAL_FATAL(secret, NULL); // bomb out if this is bad as we can't continue

    ptr = *(struct userdata *)secret->value;

    CU_ASSERT_NOT_EQUAL(strncmp("rich", ptr.name, 4), 0);
    CU_ASSERT_NOT_EQUAL(ptr.id, 1);

    expose_secret(secret, (uint8_t *)&buffer);

    CU_ASSERT_EQUAL(strncmp("rich", buffer.name, 4), 0);
    CU_ASSERT_EQUAL(buffer.id, 1);

    delete_secret(secret);

    return;
}

void test_basic_custom_struct_array(void)
{

}

void run_custom_struct_suite(void)
{
    
    CU_pSuite suite = CU_add_suite("C secrecy custom struct tests", 0, 0);
    CU_add_test(suite, "test of basic custom struct creation and destruction", test_basic_custom_struct);
    //CU_add_test(suite, "test of basic custom struct array creation and destruction", test_basic_custom_struct_array);

    CU_basic_run_tests();
}
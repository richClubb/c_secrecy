#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "test_unit_c_secrecy.h"

void main(int argc, char **argv)
{ 
    CU_initialize_registry();

    load_char_suite();
    load_float_suite();
    load_error_suite();
    load_int_suite();
    load_custom_struct_suite();

    if (argc == 1)
    {
        CU_basic_run_tests();
    }
    else if ((argc == 2) && (strlen(argv[1]) == 9) && (strncmp(argv[1], "automated", 9)))
    {
        CU_automated_run_tests();
    }

    CU_cleanup_registry();
}
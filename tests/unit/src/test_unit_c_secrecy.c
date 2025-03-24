#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "test_unit_c_secrecy.h"

void main(void)
{
    CU_initialize_registry();

    run_char_suite();
    run_float_suite();
    run_error_suite();
    run_int_suite();
    run_custom_struct_suite();
    
    CU_cleanup_registry();
}
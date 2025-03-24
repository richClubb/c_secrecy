set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "lib")

cmake_minimum_required(VERSION 3.25)

project(
    c_secrecy_unit_tests
    LANGUAGES C
)

include(CTest)

set(
    C_STANDARD 
    C11
)

#################
## Unit Tests 
#################

add_executable(
    "${PROJECT_NAME}"
    "${PROJECT_SOURCE_DIR}/src/test_unit_c_secrecy.c"
    "${PROJECT_SOURCE_DIR}/src/test_unit_c_secrecy_char.c"
    "${PROJECT_SOURCE_DIR}/src/test_unit_c_secrecy_float.c"
    "${PROJECT_SOURCE_DIR}/src/test_unit_c_secrecy_error.c"
    "${PROJECT_SOURCE_DIR}/src/test_unit_c_secrecy_int.c"
    "${PROJECT_SOURCE_DIR}/src/test_unit_c_secrecy_custom_struct.c"
)

add_test(NAME "${PROJECT_NAME}" COMMAND "${PROJECT_NAME}")

target_include_directories(
    "${PROJECT_NAME}" 
    PRIVATE 
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/../../include"
)

target_link_directories(
    "${PROJECT_NAME}" 
    PUBLIC 
    "${PROJECT_SOURCE_DIR}/../../lib"
    "/usr/lib/x86_64-linux-gnu/"
)

target_link_libraries(
    "${PROJECT_NAME}" 
    PUBLIC
    "cunit"
    "c_secrecy"
)

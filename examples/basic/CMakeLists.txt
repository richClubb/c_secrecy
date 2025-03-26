cmake_minimum_required(VERSION 3.25)

project(
    c_secrecy_basic_example
    LANGUAGES C
)

include(CTest)

set(
    C_STANDARD 
    C99
)

#################
## Unit Tests 
#################

add_executable(
    "${PROJECT_NAME}"
    "main.c"
)

add_test(NAME "${PROJECT_NAME}" COMMAND "${PROJECT_NAME}")

target_include_directories(
    "${PROJECT_NAME}" 
    PRIVATE 
    "${PROJECT_SOURCE_DIR}/../../include"
)

target_link_directories(
    "${PROJECT_NAME}" 
    PUBLIC 
    "${PROJECT_SOURCE_DIR}/../../build/lib"
)

target_link_libraries(
    "${PROJECT_NAME}" 
    PUBLIC
    "c_secrecy"
)

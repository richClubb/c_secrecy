# set(CMAKE_C_COMPILER "gcc")
# set(CMAKE_CXX_STANDARD 12)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "lib")

cmake_minimum_required(VERSION 3.25)

project(
    c_secrecy
    LANGUAGES C
)

include(CTest)

add_subdirectory("${PROJECT_SOURCE_DIR}/tests/unit")
add_subdirectory("${PROJECT_SOURCE_DIR}/examples/basic")

#################
## Main Library
#################

add_library(
    "${PROJECT_NAME}"
    SHARED
    "src/c_secrecy.c"
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

target_include_directories(
    "${PROJECT_NAME}" 
    PRIVATE 
    "include"
)

# add_custom_command(
#     TARGET 
#     "${PROJECT_NAME}" 
#     POST_BUILD
#     COMMAND 
#     ${CMAKE_COMMAND} -E copy "lib/lib${PROJECT_NAME}.so" "${PROJECT_SOURCE_DIR}/lib/"
# )

target_link_libraries(
    "${PROJECT_NAME}"
    PUBLIC
    "crypto"
)
cmake_minimum_required(VERSION 3.18)

if(NOT DEFINED CMAKE_C_COMPILER)
    find_program(NIPASS_CLANG NAMES clang-19 clang PATHS /usr/bin /usr/local/bin)
    if(NIPASS_CLANG)
        set(CMAKE_C_COMPILER "${NIPASS_CLANG}" CACHE FILEPATH "C compiler" FORCE)
    endif()
endif()

if(NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(NIPASS_CLANGXX NAMES clang++-19 clang++ PATHS /usr/bin /usr/local/bin)
    if(NIPASS_CLANGXX)
        set(CMAKE_CXX_COMPILER "${NIPASS_CLANGXX}" CACHE FILEPATH "C++ compiler" FORCE)
    endif()
endif()

project(NiPassTestX86)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(NIPASS_TEST_SOURCE_DIR "${CMAKE_SOURCE_DIR}/../tests/sources"
    CACHE PATH "Shared NiPass test source directory")

set(NIPASS_LIB "${CMAKE_SOURCE_DIR}/../lib/libNiPass-19.1.1.so"
    CACHE FILEPATH "Path to NiPass plugin .so")

option(ENABLE_OBFUSCATION "Enable NiPass obfuscation" ON)
set(NIPASS_PASSES "-enfla" CACHE STRING "NiPass -mllvm passes for fplugin mode")

if(ENABLE_OBFUSCATION AND EXISTS "${NIPASS_LIB}")
    message(STATUS "NiPass plugin: ${NIPASS_LIB}")
    add_compile_options(-fplugin=${NIPASS_LIB})
    foreach(pass ${NIPASS_PASSES})
        add_compile_options("SHELL:-mllvm ${pass}")
    endforeach()
    message(STATUS "Global passes: ${NIPASS_PASSES}")
elseif(ENABLE_OBFUSCATION)
    message(WARNING "NiPass plugin not found: ${NIPASS_LIB}, building without obfuscation")
endif()

function(add_nipass_test target source)
    if(ENABLE_OBFUSCATION AND EXISTS "${NIPASS_LIB}")
        set_source_files_properties(${source} PROPERTIES OBJECT_DEPENDS "${NIPASS_LIB}")
    endif()
    add_executable(${target} ${source})
    target_compile_options(${target} PRIVATE -O1)
endfunction()

add_nipass_test(test_nipass "${NIPASS_TEST_SOURCE_DIR}/test.c")
add_nipass_test(test_annotate "${NIPASS_TEST_SOURCE_DIR}/test_annotate.c")
add_nipass_test(test_production "${NIPASS_TEST_SOURCE_DIR}/test_production.c")
add_nipass_test(test_stl "${NIPASS_TEST_SOURCE_DIR}/test_stl.cpp")
add_nipass_test(test_template "${NIPASS_TEST_SOURCE_DIR}/test_template.cpp")

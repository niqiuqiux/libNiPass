cmake_minimum_required(VERSION 3.18)



# # 设置动态库输出位置
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_CXX_STANDARD 17)

set(platform_name "android")

if(platform_name STREQUAL "x86")
    # 允许通过环境变量指定编译器（用于 CI/CD 多版本构建）
    if(DEFINED ENV{CLANG_PATH} AND EXISTS $ENV{CLANG_PATH})
        set(CMAKE_C_COMPILER $ENV{CLANG_PATH})
        message(STATUS "使用环境变量指定的 C 编译器: $ENV{CLANG_PATH}")
    else()
        # x86 本地测试统一使用系统 LLVM，避免误用 Android prebuilts。
        find_program(CLANG_PROGRAM
            NAMES clang-19 clang
            PATHS /usr/bin /usr/local/bin
        )
        if(CLANG_PROGRAM)
            set(CMAKE_C_COMPILER ${CLANG_PROGRAM})
            message(STATUS "找到系统 C 编译器: ${CLANG_PROGRAM}")
        else()
            set(CMAKE_C_COMPILER clang)
            message(STATUS "使用默认 C 编译器: clang")
        endif()
    endif()
    
    if(DEFINED ENV{CLANGXX_PATH} AND EXISTS $ENV{CLANGXX_PATH})
        set(CMAKE_CXX_COMPILER $ENV{CLANGXX_PATH})
        message(STATUS "使用环境变量指定的 C++ 编译器: $ENV{CLANGXX_PATH}")
    else()
        find_program(CLANGXX_PROGRAM
            NAMES clang++-19 clang++
            PATHS /usr/bin /usr/local/bin
        )
        if(CLANGXX_PROGRAM)
            set(CMAKE_CXX_COMPILER ${CLANGXX_PROGRAM})
            message(STATUS "找到系统 C++ 编译器: ${CLANGXX_PROGRAM}")
        else()
            set(CMAKE_CXX_COMPILER clang++)
            message(STATUS "使用默认 C++ 编译器: clang++")
        endif()
    endif()

    if(NOT DEFINED LLVM_DIR AND EXISTS /usr/lib/llvm-19/lib/cmake/llvm)
        set(LLVM_DIR /usr/lib/llvm-19/lib/cmake/llvm CACHE PATH "Path to LLVM cmake modules" FORCE)
    endif()

else()

    if(DEFINED ENV{ccc})
    set(ccc $ENV{ccc})
    else()
    # clang-r522817 c18
    # set(ccc /home/qiu/llvm-toolchain/toolchain/llvm-project/build_r27_c18)
    set(ccc /home/qiu/llvm-toolchain/prebuilts/clang/host/linux-x86/clang-r530567)
    # set(ccc /home/ni/android-kernel/clang/clang-r487747c)
    endif()

    message(STATUS "ccc = ${ccc}")

    set(CMAKE_C_COMPILER ${ccc}/bin/clang) # 调用原生NDK的clang 来自AOSP
    set(CMAKE_CXX_COMPILER ${ccc}/bin/clang++) # 调用原生NDK的clang++ 来自AOSP
    set(ENV{LLVM_HOME} ${ccc}) # 指定LLVM_HOME为来自原生NDK的
    message(STATUS "LLVM_HOME = $ENV{LLVM_HOME}")

    if (NOT DEFINED ENV{LLVM_HOME})
    message(FATAL_ERROR "$LLVM_HOME is not defined")
    endif ()

    #  判断 $ENV{LLVM_HOME}/lib64 是否存在
    #  NDK的r25 之前的版本  存在lib64的
    if (NOT EXISTS $ENV{LLVM_HOME}/lib64)
    message(STATUS "$ENV{LLVM_HOME}/lib64 is not exists")
    set(ENV{LLVM_DIR} $ENV{LLVM_HOME}/lib/cmake/llvm)

    else ()
    message(STATUS "$ENV{LLVM_HOME}/lib64 is exists")
    set(ENV{LLVM_DIR} $ENV{LLVM_HOME}/lib64/cmake/llvm)
    endif ()
    message(STATUS "LLVM_DIR = $ENV{LLVM_DIR}")


endif()

project(MyPass)

# 查找 LLVM 包
# 如果通过 CMake 变量指定了 LLVM_DIR，优先使用
if(DEFINED LLVM_DIR)
    set(LLVM_DIR "${LLVM_DIR}" CACHE PATH "Path to LLVM cmake modules")
elseif(DEFINED ENV{LLVM_DIR})
    set(LLVM_DIR "$ENV{LLVM_DIR}" CACHE PATH "Path to LLVM cmake modules")
endif()

find_package(LLVM REQUIRED CONFIG) # 寻找LLVM依赖包
add_definitions(${LLVM_DEFINITIONS}) # 预定义

# 设置包含目录
if(DEFINED ENV{LLVM_HOME})
    include_directories($ENV{LLVM_HOME}/include) # LLVM的头文件
    # include_directories($ENV{LLVM_HOME}/include/c++/v1) # libc++的头文件包含路径
    ## 确保使用llvm的libc++ 而不是来自gcc的libstdc++
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libstdc++") # libc++ -stdlib=libstdc++

endif()
include_directories(${LLVM_INCLUDE_DIRS}) 
link_directories(${LLVM_LIBRARY_DIRS}) # LLVM依赖库



message(STATUS "LLVM_DEFINITIONS = ${LLVM_DEFINITIONS}")
message(STATUS "LLVM_DIR = ${LLVM_DIR}")
message(STATUS "LLVM_PACKAGE_VERSION = ${LLVM_PACKAGE_VERSION}")
message(STATUS "Include dirs: ${LLVM_INCLUDE_DIRS}")
message(STATUS "Libraries: ${LLVM_LIBRARIES}")


set(CMAKE_SKIP_RPATH ON)

include_directories(${CMAKE_SOURCE_DIR}/include)
# add_subdirectory(Fun)
add_subdirectory(src)


# # set(Z3_INCLUDE_DIRS "/usr/include")  # 因为 z3++.h 直接在 /usr/include
# # set(Z3_LIBRARIES "/usr/lib/x86_64-linux-gnu/libz3.so")

# # include_directories(${Z3_INCLUDE_DIRS})












cmake_minimum_required(VERSION 3.18)


# ----------------------------------------------------------------------------
# NDK 路径配置
# ----------------------------------------------------------------------------
# 优先使用环境变量 ANDROID_NDK，否则使用默认路径
if(NOT DEFINED ANDROID_NDK)
    if(WIN32)
        # Windows 默认路径，可以通过 -DANDROID_NDK=<路径> 覆盖
        set(CMAKE_ANDROID_NDK "D:/ndkollvm/android-ndk-r27c-windows/android-ndk-r27c" 
            CACHE PATH "Android NDK path")
    else()
        # Linux 默认路径
        set(CMAKE_ANDROID_NDK "/home/qiu/Android/android-ndk-r28c" 
            CACHE PATH "Android NDK path")
    endif()
else()
    set(CMAKE_ANDROID_NDK ${ANDROID_NDK})
endif()

# 设置 Android 工具链
set(CMAKE_SYSTEM_NAME ANDROID)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake)

# Android 平台配置
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-26)
set(ANDROID_NDK ${CMAKE_ANDROID_NDK})


# ============================================================================
# 项目定义
# ============================================================================
project(NiPassTestARM64)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_CXX_STANDARD 23)
set(NIPASS_TEST_SOURCE_DIR "${CMAKE_SOURCE_DIR}/../tests/sources"
    CACHE PATH "Shared NiPass test source directory")

# ============================================================================
# NiPass 插件配置
# ============================================================================
set(NIPASS_LIB "${CMAKE_SOURCE_DIR}/../lib/libNiPass-19.0.0.so"
    CACHE FILEPATH "Path to NiPass plugin .so")

# 是否启用混淆（默认开启）
option(ENABLE_OBFUSCATION "Enable NiPass obfuscation" ON)
set(NIPASS_PASSES "-enfla" CACHE STRING "NiPass -mllvm passes for fplugin mode")


if(ENABLE_OBFUSCATION AND EXISTS "${NIPASS_LIB}")
    message(STATUS "NiPass plugin: ${NIPASS_LIB}")
    # 通过 -fplugin 加载插件，并用 -mllvm 传递全局开关
    add_compile_options(-fplugin=${NIPASS_LIB})
    foreach(pass ${NIPASS_PASSES})
        add_compile_options("SHELL:-mllvm ${pass}")
    endforeach()
    message(STATUS "Global passes: ${NIPASS_PASSES}")
elseif(ENABLE_OBFUSCATION)
    message(WARNING "NiPass plugin not found: ${NIPASS_LIB}, building without obfuscation")
endif()

# ============================================================================
# 测试目标
# ============================================================================
function(add_nipass_test target source)
    if(ENABLE_OBFUSCATION AND EXISTS "${NIPASS_LIB}")
        # 插件 .so 变更后，强制相关源码重新编译，避免继续复用旧混淆产物。
        set_source_files_properties(${source} PROPERTIES OBJECT_DEPENDS "${NIPASS_LIB}")
    endif()
    add_executable(${target} ${source})
    target_compile_options(${target} PRIVATE -O1)
endfunction()

# 基础测试 - 覆盖各类混淆场景
add_nipass_test(test_nipass "${NIPASS_TEST_SOURCE_DIR}/test.c")

# 注解驱动测试 - 覆盖函数级注解与子选项
add_nipass_test(test_annotate "${NIPASS_TEST_SOURCE_DIR}/test_annotate.c")

# 生产级测试 - 模拟真实 native 库场景
add_nipass_test(test_production "${NIPASS_TEST_SOURCE_DIR}/test_production.c")

# STL 测试 - 容器/算法/智能指针/variant
add_nipass_test(test_stl "${NIPASS_TEST_SOURCE_DIR}/test_stl.cpp")

# 模板元编程测试 - CRTP/SFINAE/表达式模板/策略模式
add_nipass_test(test_template "${NIPASS_TEST_SOURCE_DIR}/test_template.cpp")

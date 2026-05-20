message(STATUS "NiPass: ${CMAKE_CURRENT_SOURCE_DIR}")

set(PASS_NAME NiPass-${LLVM_PACKAGE_VERSION})

set(EncPass
    EncPass/EnhancedStringEncryption.cpp
    EncPass/FlatteningEnhanced.cpp
    EncPass/EnVMFlatten.cpp
    EncPass/EnhancedIndirectCall.cpp
    EncPass/EnhancedIndirectBranch.cpp
)

set(Utils
    CryptoUtils.cpp
    FrontendPluginBridge.cpp
    PassRegistry.cpp
    Utils.cpp
    Fun/SubstituteImpl.cpp
    Indirect/ObfuscationOptions.cpp
)

add_library(${PASS_NAME} MODULE
${EncPass}
${Utils}
)
set_target_properties(${PASS_NAME} PROPERTIES COMPILE_FLAGS "-fno-rtti")

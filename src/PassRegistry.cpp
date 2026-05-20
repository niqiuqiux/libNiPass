#include "PassRegistry.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "EncPass/FlatteningEnhanced.h"
#include "EncPass/EnhancedStringEncryption.h"
#include "EncPass/EnVMFlatten.h"
#include "EncPass/EnhancedIndirectCall.h"
#include "EncPass/EnhancedIndirectBranch.h"
#include "Utils.h"

using namespace llvm;

// 添加命令行支持
static cl::opt<bool> s_obf_enstr("enstrenc", cl::init(false), cl::desc("Enhanced String enc: enstrcry_prob=100,enstrcry_subxor_prob=50,enstrcry_cleanup=true"));
static cl::opt<bool> s_obf_enfla("enfla", cl::init(false), cl::desc("FlatteningEnhanced"));
static cl::opt<bool> s_obf_envmf("envmf", cl::init(false), cl::desc("Enhanced VMFlatten: polymorphic dispatcher, dummy instructions, operand encoding, bytecode XOR encryption"));
static cl::opt<bool> s_obf_eicall("eicall", cl::init(false), cl::desc("Enhanced Indirect Call: per-entry keys, multi-layer XOR+ADD, index obfuscation, polymorphic decrypt"));
static cl::opt<bool> s_obf_eibr("eibr", cl::init(false), cl::desc("Enhanced Indirect Branch: per-entry keys, multi-layer XOR+ADD, index obfuscation, polymorphic decrypt, stack mode, BB shuffle"));

namespace ni_pass {

class AnnotationMetadataPass : public PassInfoMixin<AnnotationMetadataPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    annotation2Metadata(M);
    stripObfuscationAnnotations(M);
    return PreservedAnalyses::none();
  }

  static bool isRequired() { return true; }
};

void PassRegistry::registerPassBuilderCallbacks(llvm::PassBuilder &PB) {
  outs() << "Made By Ni-QiuQiu\n";
  registerAllPasses(PB);
}

void PassRegistry::registerModulePasses(llvm::PassBuilder &PB) {
  PB.registerOptimizerLastEPCallback(
    #if LLVM_VERSION_MAJOR <= 12
    [](ModulePassManager &MPM, llvm::PassBuilder::OptimizationLevel)
    #elif LLVM_VERSION_MAJOR < 20
    [](ModulePassManager &MPM, OptimizationLevel)
    #else
    [](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase Phase)
    #endif
      {
        {
          MPM.addPass(AnnotationMetadataPass());

          // 模块级 Pass
          MPM.addPass(EnhancedStringEncryptionPass(s_obf_enstr));

          // 函数级 Pass
          registerFunctionPasses(MPM);

          return true;
        }
        return false;
      });
}

void PassRegistry::registerFunctionPasses(ModulePassManager &MPM) {
  FunctionPassManager FPM;
  FPM.addPass(EnVMFlattenPass(s_obf_envmf));
  FPM.addPass(EnhancedIndirectCallPass(s_obf_eicall));
  FPM.addPass(EnhancedIndirectBranchPass(s_obf_eibr));

  MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

  // 模块级平坦化增强
  MPM.addPass(FlatteningEnhanced(s_obf_enfla));
}

void PassRegistry::registerPipelineParsingCallbacks(llvm::PassBuilder &PB) {
  // 注册EnhancedStringEncryption Pass
  PB.registerPipelineParsingCallback(
      [](StringRef Name, ModulePassManager &MPM,
         ArrayRef<PassBuilder::PipelineElement>) {
        if (Name == "enstrenc") {
          MPM.addPass(EnhancedStringEncryptionPass());
          return true;
        }
        return false;
      });

  // 注册EnhancedIndirectCall Pass
  PB.registerPipelineParsingCallback(
      [](StringRef Name, FunctionPassManager &FPM,
         ArrayRef<PassBuilder::PipelineElement>) {
        if (Name == "eicall") {
          FPM.addPass(EnhancedIndirectCallPass(true));
          return true;
        }
        return false;
      });

  // 注册EnhancedIndirectBranch Pass
  PB.registerPipelineParsingCallback(
      [](StringRef Name, FunctionPassManager &FPM,
         ArrayRef<PassBuilder::PipelineElement>) {
        if (Name == "eibr") {
          FPM.addPass(EnhancedIndirectBranchPass(true));
          return true;
        }
        return false;
      });
}

void PassRegistry::registerAllPasses(llvm::PassBuilder &PB) {
  registerModulePasses(PB);
  // registerPipelineParsingCallbacks(PB);
}

} // namespace ni_pass

// 统一的Pass注册函数
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "NiPass", LLVM_VERSION_STRING,
          [](llvm::PassBuilder &PB) {
            ni_pass::PassRegistry::registerPassBuilderCallbacks(PB);
          }};
}

// 使用方式（clang 直接调用，无需 -passes=...）
// clang-19 -fpass-plugin=./build/libMyAutoModulePass.so -O1 test.c -o test

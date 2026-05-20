#ifndef LLVM_ENHANCED_INDIRECT_CALL_H
#define LLVM_ENHANCED_INDIRECT_CALL_H

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "CryptoUtils.h"
#include "ObfuscationOptions.h"
#include "Utils.h"

using namespace llvm;

namespace ni_pass {

// 每个 callee 的独立加密信息（4 密钥 XOR-ADD 混合方案）
// 编译时加密: combined = (key1 ^ key2) + (key3 ^ key4)
//            stored   = inttoptr( ptrtoint(ptr) + combined )
// 运行时解密: combined = (key1 ^ key2) + (key3 ^ key4)
//            ptr      = inttoptr( ptrtoint(stored) - combined )
struct CalleeEncInfo {
  uint64_t key1;     // XOR 密钥对 A 的第 1 部分
  uint64_t key2;     // XOR 密钥对 A 的第 2 部分
  uint64_t key3;     // XOR 密钥对 B 的第 1 部分
  uint64_t key4;     // XOR 密钥对 B 的第 2 部分
  uint32_t variant;  // 解密模板选择器 (0/1/2)
};

class EnhancedIndirectCallPass
    : public PassInfoMixin<EnhancedIndirectCallPass> {
public:
  bool flag;
  ObfuscationOptions *Options;
  std::vector<CallInst *> CallSites;
  std::vector<Function *> Callees;
  std::map<Function *, unsigned> CalleeNumbering;
  std::map<Function *, CalleeEncInfo> CalleeKeys;
  std::map<Function *, unsigned> CalleeSlots;

  EnhancedIndirectCallPass(bool flag) {
    this->flag = flag;
    this->Options = new ObfuscationOptions;
  }

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM);
  bool doEnhancedIndirectCall(Function &Fn);
  void NumberCallees(Function &F);
  GlobalVariable *getIndirectCallees(Function &F, IntegerType *intType);
  static bool isRequired() { return true; }
};

} // namespace ni_pass

#endif // LLVM_ENHANCED_INDIRECT_CALL_H

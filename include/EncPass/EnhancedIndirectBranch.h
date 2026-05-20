#ifndef LLVM_ENHANCED_INDIRECT_BRANCH_H
#define LLVM_ENHANCED_INDIRECT_BRANCH_H

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "CryptoUtils.h"
#include "Utils.h"

#include <unordered_map>
#include <unordered_set>

using namespace llvm;

namespace ni_pass {

// 每个 BB 的独立加密信息（4 密钥 XOR-ADD 混合方案）
// 编译时加密: combined = (key1 ^ key2) + (key3 ^ key4)
//            stored   = inttoptr( ptrtoint(ptr) + combined )
// 运行时解密: combined = (key1 ^ key2) + (key3 ^ key4)
//            ptr      = inttoptr( ptrtoint(stored) - combined )
struct BBEncInfo {
  uint64_t key1;     // XOR 密钥对 A 的第 1 部分
  uint64_t key2;     // XOR 密钥对 A 的第 2 部分
  uint64_t key3;     // XOR 密钥对 B 的第 1 部分
  uint64_t key4;     // XOR 密钥对 B 的第 2 部分
  uint32_t variant;  // 解密模板选择器 (0/1/2)
};

// 每函数全局表索引编码。编译期:
//   encoded = ((real + addKey) * mulKey) ^ xorKey
// 运行时:
//   real = ((encoded ^ xorKey) * invMulKey) - addKey
struct BranchIndexCodec {
  uint64_t xorKey;
  uint64_t addKey;
  uint64_t mulKey;
  uint64_t invMulKey;
};

class EnhancedIndirectBranchPass
    : public PassInfoMixin<EnhancedIndirectBranchPass> {
public:
  bool flag;
  bool initialized;

  // 全局表相关
  GlobalVariable *GlobalTable;
  // BB → 全局表索引
  std::unordered_map<BasicBlock *, unsigned> indexmap;
  // BB → 加密信息
  std::map<BasicBlock *, BBEncInfo> BBKeys;
  // 函数 → 索引混淆参数
  std::map<Function *, BranchIndexCodec> funcIndexCodecs;
  // 需要混淆的函数集合
  std::unordered_set<Function *> to_obf_funcs;

  EnhancedIndirectBranchPass(bool flag) {
    this->flag = flag;
    this->initialized = false;
    this->GlobalTable = nullptr;
  }

  static StringRef name() { return "EnhancedIndirectBranch"; }

  bool initialize(Module &M);
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM);
  void shuffleBasicBlocks(Function &F);
  static bool isRequired() { return true; }
};

} // namespace ni_pass

#endif // LLVM_ENHANCED_INDIRECT_BRANCH_H
